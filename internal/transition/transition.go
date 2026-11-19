// Package transition stores the transition screens shown between the menu
// and an application (docs/DESIGN.md §6.5): text art a member sees when
// opening a menu item and when returning from it.
//
// A profile is a named set of text files (served over SFTP as
// /text/<slug>/) that shows either one chosen file or a random one. Each
// transition point (a menu item's enter or exit, or the default for every
// item) names the profile shown there.
package transition

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"regexp"
	"strconv"
	"time"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// Transition moments.
const (
	Enter = "enter" // opening a menu item
	Exit  = "exit"  // returning from it to the menu
)

// Profile modes.
const (
	ModeRandom = "random" // a random file each time
	ModeSingle = "single" // always the chosen file
)

// DefaultTarget is the transition point used by menu items without their
// own.
const DefaultTarget = "*"

// Limits.
const (
	MaxFileBytes = 64 << 10 // an uploaded or edited file, before cleaning
	MaxFiles     = 50       // files in one profile
	MaxProfiles  = 200
	MaxSlugLen   = 40
	MaxNameLen   = 64
)

// Errors.
var (
	ErrNotFound = errors.New("transition: not found")
	ErrExists   = errors.New("transition: a profile with that name already exists")
	ErrInvalid  = errors.New("transition: invalid")
	ErrTooMany  = errors.New("transition: limit reached")
	ErrNotEmpty = errors.New("transition: the profile still has files")
)

var (
	slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// CheckSlug validates a profile name. It is also the SFTP directory name.
func CheckSlug(slug string) error {
	if !slugRE.MatchString(slug) {
		return fmt.Errorf("%w: use 1 to %d lowercase letters, digits and hyphens, starting with a letter or digit", ErrInvalid, MaxSlugLen)
	}
	return nil
}

// CheckName validates a file name.
func CheckName(name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("%w: use 1 to %d letters, digits, dots, hyphens and underscores, starting with a letter or digit", ErrInvalid, MaxNameLen)
	}
	return nil
}

// Profile is a transition profile.
type Profile struct {
	ID    int64
	Slug  string
	Mode  string
	File  string // the chosen file, for ModeSingle
	Files int    // how many files it holds
}

// File describes a file in a profile.
type File struct {
	Name    string
	Size    int
	Updated time.Time
}

// Point is the setting of one transition point.
type Point struct {
	Target string
	Moment string
	// Set is false when the point has no setting of its own (a menu item
	// then uses the default). When Set, ProfileID 0 means "show nothing".
	Set       bool
	ProfileID int64
}

// Service reads and edits transitions.
type Service struct {
	db   *sql.DB
	now  func() time.Time
	pick func(n int) int
	log  *slog.Logger
}

// NewService returns a Service. now may be nil.
func NewService(db *sql.DB, now func() time.Time, log *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, now: now, pick: rand.IntN, log: log.With("component", "transition")}
}

// ---- reading ---------------------------------------------------------------

const profileCols = `p.id, p.slug, p.mode, p.file, (SELECT count(*) FROM transition_files f WHERE f.profile_id = p.id)`

func scanProfile(row interface{ Scan(...any) error }) (Profile, error) {
	var p Profile
	err := row.Scan(&p.ID, &p.Slug, &p.Mode, &p.File, &p.Files)
	if errors.Is(err, sql.ErrNoRows) {
		return Profile{}, ErrNotFound
	}
	return p, err
}

// Profiles returns every profile by name.
func (s *Service) Profiles(ctx context.Context) ([]Profile, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+profileCols+` FROM transition_profiles p ORDER BY p.slug`)
	if err != nil {
		return nil, fmt.Errorf("transition: profiles: %w", err)
	}
	defer rows.Close()
	var out []Profile
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ProfileBySlug returns one profile.
func (s *Service) ProfileBySlug(ctx context.Context, slug string) (Profile, error) {
	return profileBySlug(ctx, s.db, slug)
}

func profileBySlug(ctx context.Context, db store.DBTX, slug string) (Profile, error) {
	return scanProfile(db.QueryRowContext(ctx, `SELECT `+profileCols+` FROM transition_profiles p WHERE p.slug = ?`, slug))
}

// ProfileByID returns one profile.
func (s *Service) ProfileByID(ctx context.Context, id int64) (Profile, error) {
	return profileByID(ctx, s.db, id)
}

func profileByID(ctx context.Context, db store.DBTX, id int64) (Profile, error) {
	return scanProfile(db.QueryRowContext(ctx, `SELECT `+profileCols+` FROM transition_profiles p WHERE p.id = ?`, id))
}

// Files lists a profile's files by name.
func (s *Service) Files(ctx context.Context, profileID int64) ([]File, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, length(CAST(body AS BLOB)), updated_at FROM transition_files WHERE profile_id = ? ORDER BY name`, profileID)
	if err != nil {
		return nil, fmt.Errorf("transition: files: %w", err)
	}
	defer rows.Close()
	var out []File
	for rows.Next() {
		var f File
		var updated string
		if err := rows.Scan(&f.Name, &f.Size, &updated); err != nil {
			return nil, err
		}
		f.Updated, _ = store.ParseTime(updated)
		out = append(out, f)
	}
	return out, rows.Err()
}

// ReadFile returns a file's text and when it was last changed.
func (s *Service) ReadFile(ctx context.Context, profileID int64, name string) (string, time.Time, error) {
	var body, updated string
	err := s.db.QueryRowContext(ctx, `SELECT body, updated_at FROM transition_files WHERE profile_id = ? AND name = ?`, profileID, name).Scan(&body, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, ErrNotFound
	}
	if err != nil {
		return "", time.Time{}, fmt.Errorf("transition: read file: %w", err)
	}
	t, _ := store.ParseTime(updated)
	return body, t, nil
}

// Points returns every transition point that has a setting, keyed by
// PointKey.
func (s *Service) Points(ctx context.Context) (map[string]Point, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT target, moment, COALESCE(profile_id, 0) FROM transition_points`)
	if err != nil {
		return nil, fmt.Errorf("transition: points: %w", err)
	}
	defer rows.Close()
	out := map[string]Point{}
	for rows.Next() {
		p := Point{Set: true}
		if err := rows.Scan(&p.Target, &p.Moment, &p.ProfileID); err != nil {
			return nil, err
		}
		out[PointKey(p.Target, p.Moment)] = p
	}
	return out, rows.Err()
}

// PointKey names a transition point in the map Points returns.
func PointKey(target, moment string) string { return target + " " + moment }

// Pick chooses the text to show when a member reaches a transition point.
// ok is false when nothing should be shown: no profile applies, or it has
// no files.
func (s *Service) Pick(ctx context.Context, target, moment string) (text string, ok bool, err error) {
	var profileID sql.NullInt64
	err = s.db.QueryRowContext(ctx, `
		SELECT profile_id FROM transition_points WHERE moment = ? AND target IN (?, ?)
		ORDER BY target = ? LIMIT 1`, moment, target, DefaultTarget, DefaultTarget).Scan(&profileID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !profileID.Valid) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("transition: pick: %w", err)
	}
	return s.PickFrom(ctx, profileID.Int64)
}

// PickFrom chooses a file of one profile: the chosen file in single mode,
// otherwise (or if that file is gone) a random one.
func (s *Service) PickFrom(ctx context.Context, profileID int64) (string, bool, error) {
	p, err := s.ProfileByID(ctx, profileID)
	if errors.Is(err, ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if p.Mode == ModeSingle && p.File != "" {
		body, _, err := s.ReadFile(ctx, p.ID, p.File)
		if err == nil {
			return body, true, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return "", false, err
		}
		s.log.Warn("chosen transition file is missing; showing a random one", "profile", p.Slug)
	}
	if p.Files == 0 {
		return "", false, nil
	}
	var body string
	err = s.db.QueryRowContext(ctx, `SELECT body FROM transition_files WHERE profile_id = ? ORDER BY name LIMIT 1 OFFSET ?`,
		p.ID, s.pick(p.Files)).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) { // a file was removed meanwhile
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("transition: pick file: %w", err)
	}
	return body, true, nil
}

// ---- editing ----------------------------------------------------------------

// change runs fn in a transaction after checking the actor's permission,
// and audits it.
func (s *Service) change(ctx context.Context, actor, profileID int64, detail string, fn func(tx *sql.Tx) (int64, error)) error {
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := perm.RequireTx(ctx, tx, actor, perm.TransitionsManage); err != nil {
			return err
		}
		id, err := fn(tx)
		if err != nil {
			return err
		}
		if id != 0 {
			profileID = id
		}
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: audit.TransitionChanged,
			TargetType: "transition", TargetID: profileID, Detail: detail})
	})
	if err == nil {
		s.log.Info("transitions changed", "actor", actor, "change", detail)
	}
	return err
}

// slugFor names a profile in audit details, falling back to its ID if it
// cannot be read (the change itself then reports why).
func (s *Service) slugFor(ctx context.Context, id int64) string {
	if p, err := s.ProfileByID(ctx, id); err == nil {
		return p.Slug
	}
	return "#" + strconv.FormatInt(id, 10)
}

func createProfile(ctx context.Context, tx store.DBTX, now time.Time, slug string) (int64, error) {
	if err := CheckSlug(slug); err != nil {
		return 0, err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM transition_profiles`).Scan(&n); err != nil {
		return 0, err
	}
	if n >= MaxProfiles {
		return 0, fmt.Errorf("%w: at most %d profiles", ErrTooMany, MaxProfiles)
	}
	if _, err := profileBySlug(ctx, tx, slug); err == nil {
		return 0, ErrExists
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO transition_profiles (slug, created_at) VALUES (?, ?)`, slug, store.FormatTime(now))
	if err != nil {
		return 0, fmt.Errorf("transition: create profile: %w", err)
	}
	return res.LastInsertId()
}

// CreateProfile adds an empty profile that shows a random file.
func (s *Service) CreateProfile(ctx context.Context, actor int64, slug string) (int64, error) {
	var id int64
	err := s.change(ctx, actor, 0, "created profile "+slug, func(tx *sql.Tx) (int64, error) {
		var err error
		id, err = createProfile(ctx, tx, s.now(), slug)
		return id, err
	})
	return id, err
}

// UpdateProfile renames a profile and sets which file it shows. file must
// be one of its files when mode is ModeSingle.
func (s *Service) UpdateProfile(ctx context.Context, actor, id int64, slug, mode, file string) error {
	if err := CheckSlug(slug); err != nil {
		return err
	}
	switch mode {
	case ModeRandom:
		file = ""
	case ModeSingle:
	default:
		return fmt.Errorf("%w: unknown mode %q", ErrInvalid, mode)
	}
	return s.change(ctx, actor, id, "updated profile "+s.slugFor(ctx, id)+" (now "+slug+", "+mode+")", func(tx *sql.Tx) (int64, error) {
		if _, err := profileByID(ctx, tx, id); err != nil {
			return 0, err
		}
		if other, err := profileBySlug(ctx, tx, slug); err == nil && other.ID != id {
			return 0, ErrExists
		}
		if mode == ModeSingle {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM transition_files WHERE profile_id = ? AND name = ?`, id, file).Scan(&n); err != nil {
				return 0, err
			}
			if n == 0 {
				return 0, fmt.Errorf("%w: choose one of the profile's files", ErrInvalid)
			}
		}
		_, err := tx.ExecContext(ctx, `UPDATE transition_profiles SET slug = ?, mode = ?, file = ? WHERE id = ?`, slug, mode, file, id)
		return 0, err
	})
}

// DeleteProfile removes a profile and its files. Transition points that
// used it fall back to the default. With onlyEmpty, a profile that still
// has files is refused with ErrNotEmpty (SFTP rmdir).
func (s *Service) DeleteProfile(ctx context.Context, actor, id int64, onlyEmpty bool) error {
	return s.change(ctx, actor, id, "deleted profile "+s.slugFor(ctx, id), func(tx *sql.Tx) (int64, error) {
		p, err := profileByID(ctx, tx, id)
		if err != nil {
			return 0, err
		}
		if onlyEmpty && p.Files > 0 {
			return 0, ErrNotEmpty
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM transition_profiles WHERE id = ?`, id)
		return 0, err
	})
}

func saveFile(ctx context.Context, tx store.DBTX, now time.Time, profileID int64, name, body string) error {
	var exists, n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FILTER (WHERE name = ?), count(*) FROM transition_files WHERE profile_id = ?`,
		name, profileID).Scan(&exists, &n); err != nil {
		return err
	}
	if exists == 0 && n >= MaxFiles {
		return fmt.Errorf("%w: at most %d files in a profile", ErrTooMany, MaxFiles)
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO transition_files (profile_id, name, body, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (profile_id, name) DO UPDATE SET body = excluded.body, updated_at = excluded.updated_at`,
		profileID, name, body, store.FormatTime(now))
	if err != nil {
		return fmt.Errorf("transition: save file: %w", err)
	}
	return nil
}

// SaveFile creates or replaces a file in a profile. data is cleaned with
// Clean first.
func (s *Service) SaveFile(ctx context.Context, actor, profileID int64, name string, data []byte) error {
	if err := CheckName(name); err != nil {
		return err
	}
	body, err := Clean(data)
	if err != nil {
		return err
	}
	return s.change(ctx, actor, profileID, "saved file "+s.slugFor(ctx, profileID)+"/"+name, func(tx *sql.Tx) (int64, error) {
		if _, err := profileByID(ctx, tx, profileID); err != nil {
			return 0, err
		}
		return 0, saveFile(ctx, tx, s.now(), profileID, name, body)
	})
}

// Upload stores a file sent over SFTP to /text/<slug>/<name>, creating the
// profile if it does not exist yet.
func (s *Service) Upload(ctx context.Context, actor int64, slug, name string, data []byte) error {
	if err := CheckSlug(slug); err != nil {
		return err
	}
	if err := CheckName(name); err != nil {
		return err
	}
	body, err := Clean(data)
	if err != nil {
		return err
	}
	return s.change(ctx, actor, 0, "uploaded "+slug+"/"+name, func(tx *sql.Tx) (int64, error) {
		p, err := profileBySlug(ctx, tx, slug)
		if errors.Is(err, ErrNotFound) {
			p.ID, err = createProfile(ctx, tx, s.now(), slug)
		}
		if err != nil {
			return 0, err
		}
		return p.ID, saveFile(ctx, tx, s.now(), p.ID, name, body)
	})
}

// DeleteFile removes a file from a profile. If it was the chosen file, the
// profile shows a random file until another is chosen.
func (s *Service) DeleteFile(ctx context.Context, actor, profileID int64, name string) error {
	return s.change(ctx, actor, profileID, "deleted file "+s.slugFor(ctx, profileID)+"/"+name, func(tx *sql.Tx) (int64, error) {
		res, err := tx.ExecContext(ctx, `DELETE FROM transition_files WHERE profile_id = ? AND name = ?`, profileID, name)
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return 0, ErrNotFound
		}
		_, err = tx.ExecContext(ctx, `UPDATE transition_profiles SET mode = ?, file = '' WHERE id = ? AND file = ?`, ModeRandom, profileID, name)
		return 0, err
	})
}

// Choice is what a transition point is set to.
type Choice struct {
	Inherit   bool  // no setting of its own: use the default (items only)
	ProfileID int64 // 0 with Inherit false = show nothing
}

// SetPoint sets a transition point. target is a menu item or
// DefaultTarget; known reports whether a menu item exists.
func (s *Service) SetPoint(ctx context.Context, actor int64, target, moment string, c Choice, known func(string) bool) error {
	if moment != Enter && moment != Exit {
		return fmt.Errorf("%w: unknown moment %q", ErrInvalid, moment)
	}
	if target != DefaultTarget && !known(target) {
		return fmt.Errorf("%w: unknown menu item %q", ErrInvalid, target)
	}
	if target == DefaultTarget && c.Inherit { // the default has nothing to inherit
		c = Choice{}
	}
	detail := "set " + target + " " + moment
	return s.change(ctx, actor, c.ProfileID, detail, func(tx *sql.Tx) (int64, error) {
		if c.Inherit {
			_, err := tx.ExecContext(ctx, `DELETE FROM transition_points WHERE target = ? AND moment = ?`, target, moment)
			return 0, err
		}
		var profile any
		if c.ProfileID != 0 {
			if _, err := profileByID(ctx, tx, c.ProfileID); err != nil {
				return 0, err
			}
			profile = c.ProfileID
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO transition_points (target, moment, profile_id) VALUES (?, ?, ?)
			ON CONFLICT (target, moment) DO UPDATE SET profile_id = excluded.profile_id`, target, moment, profile)
		return 0, err
	})
}
