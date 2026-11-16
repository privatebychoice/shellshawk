// Package menu stores the configurable member menu (docs/DESIGN.md §3.2): a
// tree of entries, each either a menu item ("<owner>:<key>", provided by core
// or a plugin) or a submenu. Administrators with core.menu.manage edit it.
package menu

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Entry kinds.
const (
	KindItem    = "item"
	KindSubmenu = "submenu"
)

// Protected targets can be moved and renamed but never deleted, so an
// administrator cannot lock everyone (including themselves) out of the
// admin menu or of logging out.
const (
	TargetAdmin  = "core:admin"
	TargetLogout = "core:logout"
)

// MaxLabelLen bounds menu labels.
const MaxLabelLen = 40

// Errors.
var (
	ErrNotFound  = errors.New("menu entry not found")
	ErrProtected = errors.New("this entry cannot be deleted")
	ErrNotEmpty  = errors.New("remove the entries in this submenu first")
	ErrInvalid   = errors.New("invalid menu entry")
)

// Entry is one menu entry. ParentID 0 means the main menu.
type Entry struct {
	ID         int64
	ParentID   int64
	Position   int
	Label      string
	Kind       string
	Target     string // menu item, for KindItem
	Permission string // extra permission required, if any
}

// Default is a menu item to place in the main menu automatically.
type Default struct {
	Target string
	Label  string
}

// Service reads and edits the menu.
type Service struct {
	db    *sql.DB
	perms *perm.Service
	now   func() time.Time
	log   *slog.Logger
}

// NewService returns a Service. now may be nil.
func NewService(db *sql.DB, perms *perm.Service, now func() time.Time, log *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, perms: perms, now: now, log: log.With("component", "menu")}
}

const entryCols = `id, COALESCE(parent_id, 0), position, label, kind, target, permission`

func scan(row interface{ Scan(...any) error }) (Entry, error) {
	var e Entry
	err := row.Scan(&e.ID, &e.ParentID, &e.Position, &e.Label, &e.Kind, &e.Target, &e.Permission)
	return e, err
}

func list(ctx context.Context, db store.DBTX, where string, args ...any) ([]Entry, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+entryCols+` FROM menu_entries `+where+` ORDER BY position, id`, args...)
	if err != nil {
		return nil, fmt.Errorf("menu: list: %w", err)
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func parentClause(parent int64) (string, []any) {
	if parent == 0 {
		return "WHERE parent_id IS NULL", nil
	}
	return "WHERE parent_id = ?", []any{parent}
}

// Children returns the entries of a submenu (0 = main menu) in order.
func (s *Service) Children(ctx context.Context, parent int64) ([]Entry, error) {
	w, args := parentClause(parent)
	return list(ctx, s.db, w, args...)
}

// Get returns one entry.
func (s *Service) Get(ctx context.Context, id int64) (Entry, error) {
	e, err := scan(s.db.QueryRowContext(ctx, `SELECT `+entryCols+` FROM menu_entries WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, ErrNotFound
	}
	return e, err
}

// CleanLabel trims and validates a label.
func CleanLabel(l string) (string, error) {
	l = strings.TrimSpace(l)
	if n := utf8.RuneCountInString(l); n == 0 || n > MaxLabelLen || term.Sanitize(l, false) != l {
		return "", fmt.Errorf("%w: label must be 1 to %d printable characters", ErrInvalid, MaxLabelLen)
	}
	return l, nil
}

// Add creates an entry at the end of parent (0 = main menu). known reports
// whether an item target exists.
func (s *Service) Add(ctx context.Context, actor int64, e Entry, known func(string) bool) (int64, error) {
	label, err := CleanLabel(e.Label)
	if err != nil {
		return 0, err
	}
	switch e.Kind {
	case KindItem:
		if !known(e.Target) {
			return 0, fmt.Errorf("%w: unknown menu item %q", ErrInvalid, e.Target)
		}
	case KindSubmenu:
		e.Target = ""
	default:
		return 0, fmt.Errorf("%w: unknown kind %q", ErrInvalid, e.Kind)
	}
	if e.Permission != "" && !s.perms.Registry().Known(e.Permission) {
		return 0, fmt.Errorf("%w: unknown permission %q", ErrInvalid, e.Permission)
	}
	var id int64
	err = s.change(ctx, actor, "added "+label, func(tx *sql.Tx) error {
		var parent any
		if e.ParentID != 0 {
			var kind string
			if err := tx.QueryRowContext(ctx, `SELECT kind FROM menu_entries WHERE id = ?`, e.ParentID).Scan(&kind); err != nil {
				return ErrNotFound
			}
			if kind != KindSubmenu {
				return fmt.Errorf("%w: parent is not a submenu", ErrInvalid)
			}
			parent = e.ParentID
		}
		pos, err := nextPosition(ctx, tx, e.ParentID)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO menu_entries (parent_id, position, label, kind, target, permission, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, parent, pos, label, e.Kind, e.Target, e.Permission, store.FormatTime(s.now()))
		if err != nil {
			return fmt.Errorf("menu: add: %w", err)
		}
		id, _ = res.LastInsertId()
		return nil
	})
	return id, err
}

func nextPosition(ctx context.Context, tx store.DBTX, parent int64) (int, error) {
	w, args := parentClause(parent)
	var pos int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(position), 0) + 1 FROM menu_entries `+w, args...).Scan(&pos); err != nil {
		return 0, fmt.Errorf("menu: position: %w", err)
	}
	return pos, nil
}

// Update changes an entry's label and extra permission.
func (s *Service) Update(ctx context.Context, actor, id int64, label, permission string) error {
	label, err := CleanLabel(label)
	if err != nil {
		return err
	}
	if permission != "" && !s.perms.Registry().Known(permission) {
		return fmt.Errorf("%w: unknown permission %q", ErrInvalid, permission)
	}
	return s.change(ctx, actor, "updated "+label, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE menu_entries SET label = ?, permission = ? WHERE id = ?`, label, permission, id)
		if err != nil {
			return fmt.Errorf("menu: update: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// Move swaps an entry with its previous (delta < 0) or next (delta > 0)
// sibling. Moving past either end does nothing.
func (s *Service) Move(ctx context.Context, actor, id int64, delta int) error {
	return s.change(ctx, actor, "moved entry "+strconv.FormatInt(id, 10), func(tx *sql.Tx) error {
		e, err := scan(tx.QueryRowContext(ctx, `SELECT `+entryCols+` FROM menu_entries WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		w, args := parentClause(e.ParentID)
		sibs, err := list(ctx, tx, w, args...)
		if err != nil {
			return err
		}
		i := -1
		for j, sb := range sibs {
			if sb.ID == id {
				i = j
			}
		}
		k := i + 1
		if delta < 0 {
			k = i - 1
		}
		if i < 0 || k < 0 || k >= len(sibs) {
			return nil
		}
		// Rewrite positions densely with the two entries swapped.
		sibs[i], sibs[k] = sibs[k], sibs[i]
		for p, sb := range sibs {
			if _, err := tx.ExecContext(ctx, `UPDATE menu_entries SET position = ? WHERE id = ?`, p+1, sb.ID); err != nil {
				return fmt.Errorf("menu: move: %w", err)
			}
		}
		return nil
	})
}

// Delete removes an entry. Protected items and non-empty submenus cannot be
// deleted.
func (s *Service) Delete(ctx context.Context, actor, id int64) error {
	return s.change(ctx, actor, "deleted entry "+strconv.FormatInt(id, 10), func(tx *sql.Tx) error {
		e, err := scan(tx.QueryRowContext(ctx, `SELECT `+entryCols+` FROM menu_entries WHERE id = ?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if e.Target == TargetAdmin || e.Target == TargetLogout {
			return ErrProtected
		}
		var children int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM menu_entries WHERE parent_id = ?`, id).Scan(&children); err != nil {
			return err
		}
		if children > 0 {
			return ErrNotEmpty
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM menu_entries WHERE id = ?`, id)
		return err
	})
}

// change runs fn in a transaction after checking core.menu.manage, and
// audits it.
func (s *Service) change(ctx context.Context, actor int64, detail string, fn func(tx *sql.Tx) error) error {
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := perm.RequireTx(ctx, tx, actor, perm.MenuManage); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: audit.MenuChanged, TargetType: "menu", Detail: detail})
	})
	if err == nil {
		s.log.Info("menu changed", "actor", actor, "change", detail)
	}
	return err
}

// Seed adds each default item to the main menu the first time it is seen,
// placing new items just before Log out. Items an administrator later
// removes are not added again.
func (s *Service) Seed(ctx context.Context, defaults []Default) error {
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error { return seed(ctx, tx, s.now(), defaults, s.log) })
}

func seed(ctx context.Context, tx *sql.Tx, now time.Time, defaults []Default, log *slog.Logger) error {
	for _, d := range defaults {
		res, err := tx.ExecContext(ctx, `INSERT INTO menu_seeded (target) VALUES (?) ON CONFLICT DO NOTHING`, d.Target)
		if err != nil {
			return fmt.Errorf("menu: seed: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			continue
		}
		pos, err := nextPosition(ctx, tx, 0)
		if err != nil {
			return err
		}
		if d.Target != TargetLogout {
			var logoutPos int
			err := tx.QueryRowContext(ctx, `SELECT position FROM menu_entries WHERE parent_id IS NULL AND target = ?`, TargetLogout).Scan(&logoutPos)
			if err == nil {
				pos = logoutPos
				if _, err := tx.ExecContext(ctx, `UPDATE menu_entries SET position = position + 1 WHERE parent_id IS NULL AND position >= ?`, pos); err != nil {
					return fmt.Errorf("menu: seed: %w", err)
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO menu_entries (parent_id, position, label, kind, target, created_at)
			VALUES (NULL, ?, ?, ?, ?, ?)`, pos, d.Label, KindItem, d.Target, store.FormatTime(now)); err != nil {
			return fmt.Errorf("menu: seed: %w", err)
		}
		log.Info("menu item added to main menu", "target", d.Target)
	}
	return nil
}

// Reset discards every entry and rebuilds the default main menu.
func (s *Service) Reset(ctx context.Context, actor int64, defaults []Default) error {
	return s.change(ctx, actor, "reset to default", func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM menu_entries`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM menu_seeded`); err != nil {
			return err
		}
		return seed(ctx, tx, s.now(), defaults, s.log)
	})
}
