// Package privacy holds member profile fields and their visibility, the
// rules for who may see or contact whom, the member data export, and
// account erasure (docs/DESIGN.md §5).
package privacy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Level is who may see a field (or contact the member).
type Level string

const (
	Public  Level = "public"
	Friends Level = "friends" // members who have each other as contacts
	NoOne   Level = "none"
)

// LevelLabel describes a level in words.
func LevelLabel(l Level) string {
	switch l {
	case Public:
		return "Everyone"
	case Friends:
		return "Friends only"
	}
	return "No one"
}

// Field is something a member controls the visibility of.
type Field string

const (
	FullName  Field = "full_name"
	Email     Field = "email"
	Phone     Field = "phone"
	Status    Field = "status"
	LastLogin Field = "last_login"
	Messages  Field = "messages" // who may send me private messages
	Pages     Field = "pages"    // who may page me (ask to talk in chat)
	Online    Field = "online"   // who may see that I am online
)

// Fields lists every field in display order with its description.
var Fields = []struct {
	Field Field
	Label string
}{
	{FullName, "Full name"},
	{Email, "Email address"},
	{Phone, "Phone number"},
	{Status, "Status message"},
	{LastLogin, "Last login time"},
	{Online, "That you are online now"},
	{Messages, "Who can send you private messages"},
	{Pages, "Who can page you (ask you to talk in chat); they must also be able to see that you are online"},
}

// Defaults are privacy-first: members opt in to sharing.
var Defaults = map[Field]Level{
	FullName: NoOne, Email: NoOne, Phone: NoOne, Status: Friends,
	LastLogin: NoOne, Messages: Friends, Online: Friends, Pages: Friends,
}

// Profile limits.
const (
	MaxFullName = 100
	MaxStatus   = 140
)

// ErrInvalid is returned for invalid profile values.
var ErrInvalid = errors.New("invalid profile")

// FriendChecker reports whether two members have each other as contacts.
// The Contacts plugin implements it.
type FriendChecker interface {
	IsFriend(ctx context.Context, a, b int64) (bool, error)
}

// Service manages profiles, visibility and erasure.
type Service struct {
	db      *sql.DB
	auth    *auth.Service
	perms   *perm.Service
	friends FriendChecker
	grace   time.Duration
	events  Publisher // may be nil
	now     func() time.Time
	log     *slog.Logger
}

// NewService returns a Service. grace is how long an erasure request waits
// before the account is erased. now may be nil.
func NewService(db *sql.DB, a *auth.Service, p *perm.Service, grace time.Duration, now func() time.Time, log *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, auth: a, perms: p, grace: grace, now: now, log: log.With("component", "privacy")}
}

// SetPublisher makes the service publish ErasureRequested, and
// UserUnlocked when a request is cancelled, after each change commits.
func (s *Service) SetPublisher(p Publisher) { s.events = p }

// publish delivers e after a change has committed. Delivery must finish
// even if ctx ends meanwhile: a member asking for erasure does so from a
// session that the ErasureRequested handlers themselves end, and a later
// handler (such as the one deleting web sessions) still has to run.
func (s *Service) publish(ctx context.Context, e events.Event) {
	if s.events != nil {
		_ = s.events.Publish(context.WithoutCancel(ctx), e)
	}
}

// SetFriends installs the friend relation. Without one, "Friends only"
// fields are visible to nobody but the member.
func (s *Service) SetFriends(f FriendChecker) { s.friends = f }

// Profile is a member's profile and visibility choices.
type Profile struct {
	FullName   string
	Email      string
	Phone      string
	Status     string
	Visibility map[Field]Level
}

// Get returns a member's own profile with every level filled in.
func (s *Service) Get(ctx context.Context, userID int64) (Profile, error) {
	u, err := s.auth.UserByID(ctx, userID)
	if err != nil {
		return Profile{}, err
	}
	p := Profile{Email: u.Email, Visibility: map[Field]Level{}}
	err = s.db.QueryRowContext(ctx, `SELECT full_name, phone, status_text FROM user_profiles WHERE user_id = ?`, userID).
		Scan(&p.FullName, &p.Phone, &p.Status)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Profile{}, fmt.Errorf("privacy: profile: %w", err)
	}
	for f, l := range Defaults {
		p.Visibility[f] = l
	}
	rows, err := s.db.QueryContext(ctx, `SELECT field, level FROM user_visibility WHERE user_id = ?`, userID)
	if err != nil {
		return Profile{}, fmt.Errorf("privacy: visibility: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var f, l string
		if err := rows.Scan(&f, &l); err != nil {
			return Profile{}, err
		}
		if _, known := Defaults[Field(f)]; known {
			p.Visibility[Field(f)] = Level(l)
		}
	}
	return p, rows.Err()
}

func validLevel(l Level) bool { return l == Public || l == Friends || l == NoOne }

// Update stores a member's profile and visibility choices.
func (s *Service) Update(ctx context.Context, userID int64, p Profile) error {
	name := strings.TrimSpace(p.FullName)
	status := strings.TrimSpace(p.Status)
	if utf8.RuneCountInString(name) > MaxFullName || term.Sanitize(name, false) != name {
		return fmt.Errorf("%w: full name must be at most %d printable characters", ErrInvalid, MaxFullName)
	}
	if utf8.RuneCountInString(status) > MaxStatus || term.Sanitize(status, false) != status {
		return fmt.Errorf("%w: status must be at most %d printable characters", ErrInvalid, MaxStatus)
	}
	phone := strings.TrimSpace(p.Phone)
	if phone != "" {
		var err error
		if phone, err = form.ValidatePhone(phone); err != nil {
			return fmt.Errorf("%w: phone %v", ErrInvalid, err)
		}
	}
	email, err := auth.NormalizeEmail(p.Email)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	for f, l := range p.Visibility {
		if _, known := Defaults[f]; !known || !validLevel(l) {
			return fmt.Errorf("%w: bad visibility for %s", ErrInvalid, f)
		}
	}
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		now := store.FormatTime(s.now())
		var emailArg any
		if email != "" {
			emailArg = email
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET email = ? WHERE id = ?`, emailArg, userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_profiles (user_id, full_name, phone, status_text, updated_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (user_id) DO UPDATE SET full_name = excluded.full_name, phone = excluded.phone,
				status_text = excluded.status_text, updated_at = excluded.updated_at`, userID, name, phone, status, now); err != nil {
			return err
		}
		for f, l := range p.Visibility {
			if _, err := tx.ExecContext(ctx, `INSERT INTO user_visibility (user_id, field, level) VALUES (?, ?, ?)
				ON CONFLICT (user_id, field) DO UPDATE SET level = excluded.level`, userID, string(f), string(l)); err != nil {
				return err
			}
		}
		s.log.Info("profile updated", "user_id", userID)
		return nil
	})
}

// Allows reports whether viewer may see field of owner (or, for Messages
// and Pages, send owner a private message or page them). Members always see their own data.
func (s *Service) Allows(ctx context.Context, viewer, owner int64, f Field) (bool, error) {
	if viewer == owner {
		return true, nil
	}
	level := Defaults[f]
	var stored string
	err := s.db.QueryRowContext(ctx, `SELECT level FROM user_visibility WHERE user_id = ? AND field = ?`, owner, string(f)).Scan(&stored)
	switch {
	case err == nil:
		level = Level(stored)
	case !errors.Is(err, sql.ErrNoRows):
		return false, err
	}
	switch level {
	case Public:
		return true, nil
	case Friends:
		if s.friends == nil {
			return false, nil
		}
		return s.friends.IsFriend(ctx, viewer, owner)
	}
	return false, nil
}

// Visible is what a viewer may see of another member's profile. Empty
// fields are either unset or hidden from this viewer.
type Visible struct {
	FullName, Email, Phone, Status string
	LastLogin                      *time.Time
}

// View returns the parts of owner's profile viewer may see.
func (s *Service) View(ctx context.Context, viewer, owner int64) (Visible, error) {
	p, err := s.Get(ctx, owner)
	if err != nil {
		return Visible{}, err
	}
	u, err := s.auth.UserByID(ctx, owner)
	if err != nil {
		return Visible{}, err
	}
	var v Visible
	for _, x := range []struct {
		f   Field
		set func()
	}{
		{FullName, func() { v.FullName = p.FullName }},
		{Email, func() { v.Email = p.Email }},
		{Phone, func() { v.Phone = p.Phone }},
		{Status, func() { v.Status = p.Status }},
		{LastLogin, func() { v.LastLogin = u.LastLoginAt }},
	} {
		ok, err := s.Allows(ctx, viewer, owner, x.f)
		if err != nil {
			return Visible{}, err
		}
		if ok {
			x.set()
		}
	}
	return v, nil
}

// AdminEmail returns a member's email address to staff with
// core.users.manage who outrank the member (perm.RequireOutranks),
// whatever the member's visibility setting, and records the access in the
// audit log (docs/DESIGN.md §5.1).
func (s *Service) AdminEmail(ctx context.Context, actor, target int64) (string, error) {
	var email string
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		// The rank rule, as for locking: staff cannot read the address of
		// an account holding permissions they lack (a moderator, an
		// administrator's).
		if err := perm.RequireOutranks(ctx, tx, actor, target, perm.UsersManage); err != nil {
			return err
		}
		u, err := s.auth.UserByID(ctx, target)
		if err != nil {
			return err
		}
		email = u.Email
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: audit.AdminViewedEmail, TargetType: "user", TargetID: target})
	})
	if err != nil {
		return "", err
	}
	s.log.Info("administrator viewed email", "actor", actor, "user_id", target)
	return email, nil
}
