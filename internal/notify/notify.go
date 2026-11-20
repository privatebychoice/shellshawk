// Package notify stores members' notifications (docs/DESIGN.md §6.6):
// short notices about something that happened elsewhere, such as a page, a
// new private message or a reply to a member's thread.
//
// Plugins declare the kinds they send in their manifest; members choose
// which kinds they receive. The BBS shows new notifications between
// screens and lists them under Notifications; opening one hands it back to
// the plugin that sent it.
package notify

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Limits.
const (
	// Keep is how many notifications a member keeps; older ones are
	// deleted when a new one arrives.
	Keep = 100
	// MaxAge is how long a notification is kept.
	MaxAge  = 30 * 24 * time.Hour
	MaxText = 120 // characters of description
	MaxRef  = 64
)

// Errors.
var (
	ErrNotFound = errors.New("notify: not found")
	ErrInvalid  = errors.New("notify: invalid")
)

var kindPattern = regexp.MustCompile(`^[a-z][a-z0-9]{1,30}:[a-z][a-z0-9-]{0,31}$`)

// Kind is a kind of notification a plugin sends.
type Kind struct {
	Name    string // "<plugin>:<key>"
	Label   string // e.g. "Pages", shown in the member's settings
	Help    string
	Default bool // received unless the member turns it off
}

// Notification is one notice for a member.
type Notification struct {
	ID      int64
	UserID  int64
	Kind    string
	ActorID int64  // 0 if nobody (or the account is gone)
	Actor   string // the actor's username, "" if none
	Text    string
	Ref     string
	Created time.Time
	Seen    bool
}

// New is a notification to add.
type New struct {
	UserID  int64
	Kind    string
	ActorID int64
	Text    string
	Ref     string
}

// Service stores notifications.
type Service struct {
	db   *sql.DB
	auth *auth.Service
	now  func() time.Time
	log  *slog.Logger

	mu    sync.RWMutex
	kinds []Kind
}

// NewService returns a Service. now may be nil.
func NewService(db *sql.DB, a *auth.Service, now func() time.Time, log *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, auth: a, now: now, log: log.With("component", "notify")}
}

// Subscribe removes a member's notifications, and those they caused, when
// their account is erased.
func (s *Service) Subscribe(bus *events.Bus) {
	bus.Subscribe(events.UserErased, "notify", func(ctx context.Context, e events.Event) error {
		_, err := s.db.ExecContext(ctx, `DELETE FROM notifications WHERE user_id = ? OR actor_id = ?`, e.UserID, e.UserID)
		if err == nil {
			_, err = s.db.ExecContext(ctx, `DELETE FROM notification_settings WHERE user_id = ?`, e.UserID)
		}
		return err
	})
}

// Register declares a kind. Plugins' kinds are registered when they load.
func (s *Service) Register(k Kind) error {
	if !kindPattern.MatchString(k.Name) || k.Label == "" {
		return fmt.Errorf("%w: kind %q", ErrInvalid, k.Name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, have := range s.kinds {
		if have.Name == k.Name {
			return fmt.Errorf("%w: duplicate kind %q", ErrInvalid, k.Name)
		}
	}
	s.kinds = append(s.kinds, k)
	return nil
}

// Kinds returns the registered kinds in registration order.
func (s *Service) Kinds() []Kind {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Kind(nil), s.kinds...)
}

// Kind returns a registered kind.
func (s *Service) Kind(name string) (Kind, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range s.kinds {
		if k.Name == name {
			return k, true
		}
	}
	return Kind{}, false
}

// Settings returns which kinds userID receives, for every registered kind.
func (s *Service) Settings(ctx context.Context, userID int64) (map[string]bool, error) {
	out := map[string]bool{}
	for _, k := range s.Kinds() {
		out[k.Name] = k.Default
	}
	rows, err := s.db.QueryContext(ctx, `SELECT kind, enabled FROM notification_settings WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("notify: settings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var k string
		var on bool
		if err := rows.Scan(&k, &on); err != nil {
			return nil, err
		}
		if _, known := out[k]; known {
			out[k] = on
		}
	}
	return out, rows.Err()
}

// Enabled reports whether userID receives kind. Unknown kinds are off.
func (s *Service) Enabled(ctx context.Context, userID int64, kind string) (bool, error) {
	k, ok := s.Kind(kind)
	if !ok {
		return false, nil
	}
	var on bool
	err := s.db.QueryRowContext(ctx, `SELECT enabled FROM notification_settings WHERE user_id = ? AND kind = ?`, userID, kind).Scan(&on)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return k.Default, nil
	case err != nil:
		return false, fmt.Errorf("notify: enabled: %w", err)
	}
	return on, nil
}

// SetSettings stores which kinds userID receives. Kinds not in on are left
// as they are; unknown kinds are refused.
func (s *Service) SetSettings(ctx context.Context, userID int64, on map[string]bool) error {
	for k := range on {
		if _, ok := s.Kind(k); !ok {
			return fmt.Errorf("%w: unknown kind %q", ErrInvalid, k)
		}
	}
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		for k, v := range on {
			if _, err := tx.ExecContext(ctx, `INSERT INTO notification_settings (user_id, kind, enabled) VALUES (?, ?, ?)
				ON CONFLICT (user_id, kind) DO UPDATE SET enabled = excluded.enabled`, userID, k, v); err != nil {
				return fmt.Errorf("notify: settings: %w", err)
			}
		}
		s.log.Info("notification settings changed", "user_id", userID)
		return nil
	})
}

// clean makes a description safe to show: one line of printable text, cut
// to MaxText characters.
func clean(text string) string {
	text = strings.Join(strings.Fields(term.Sanitize(text, false)), " ")
	if utf8.RuneCountInString(text) > MaxText {
		r := []rune(text)
		text = strings.TrimSpace(string(r[:MaxText-1])) + "…"
	}
	return text
}

// Add stores a notification if the member receives its kind, and reports
// whether it did. The member's oldest notifications beyond Keep, and any
// older than MaxAge, are deleted.
func (s *Service) Add(ctx context.Context, n New) (int64, bool, error) {
	if len(n.Ref) > MaxRef {
		return 0, false, fmt.Errorf("%w: reference too long", ErrInvalid)
	}
	on, err := s.Enabled(ctx, n.UserID, n.Kind)
	if err != nil || !on {
		return 0, false, err
	}
	var actor any
	if n.ActorID != 0 {
		actor = n.ActorID
	}
	now := s.now()
	var id int64
	err = store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO notifications (user_id, kind, actor_id, text, ref, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			n.UserID, n.Kind, actor, clean(n.Text), n.Ref, store.FormatTime(now))
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId()
		return prune(ctx, tx, n.UserID, now)
	})
	if err != nil {
		return 0, false, fmt.Errorf("notify: add: %w", err)
	}
	s.log.Debug("notification added", "user_id", n.UserID, "kind", n.Kind, "id", id)
	return id, true, nil
}

func prune(ctx context.Context, db store.DBTX, userID int64, now time.Time) error {
	_, err := db.ExecContext(ctx, `DELETE FROM notifications WHERE user_id = ? AND (created_at < ? OR id NOT IN
		(SELECT id FROM notifications WHERE user_id = ? ORDER BY created_at DESC, id DESC LIMIT ?))`,
		userID, store.FormatTime(now.Add(-MaxAge)), userID, Keep)
	return err
}

const cols = `id, user_id, kind, COALESCE(actor_id, 0), text, ref, created_at, seen_at IS NOT NULL`

func (s *Service) query(ctx context.Context, q string, args ...any) ([]Notification, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+cols+` FROM notifications `+q, args...)
	if err != nil {
		return nil, fmt.Errorf("notify: list: %w", err)
	}
	var out []Notification
	var actors []int64
	for rows.Next() {
		var n Notification
		var created string
		if err := rows.Scan(&n.ID, &n.UserID, &n.Kind, &n.ActorID, &n.Text, &n.Ref, &created, &n.Seen); err != nil {
			rows.Close()
			return nil, err
		}
		n.Created, _ = store.ParseTime(created)
		if n.ActorID != 0 {
			actors = append(actors, n.ActorID)
		}
		out = append(out, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(actors) > 0 {
		names, err := s.auth.Usernames(ctx, actors)
		if err != nil {
			return nil, err
		}
		for i := range out {
			out[i].Actor = names[out[i].ActorID]
		}
	}
	return out, nil
}

// List returns userID's notifications, newest first, after deleting
// expired ones.
func (s *Service) List(ctx context.Context, userID int64) ([]Notification, error) {
	if err := prune(ctx, s.db, userID, s.now()); err != nil {
		return nil, fmt.Errorf("notify: prune: %w", err)
	}
	return s.query(ctx, `WHERE user_id = ? ORDER BY created_at DESC, id DESC`, userID)
}

// Unseen returns userID's notifications not shown yet, oldest first.
func (s *Service) Unseen(ctx context.Context, userID int64) ([]Notification, error) {
	return s.query(ctx, `WHERE user_id = ? AND seen_at IS NULL ORDER BY created_at, id`, userID)
}

// CountUnseen returns how many of userID's notifications are new.
func (s *Service) CountUnseen(ctx context.Context, userID int64) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM notifications WHERE user_id = ? AND seen_at IS NULL`, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("notify: count: %w", err)
	}
	return n, nil
}

// Get returns one of userID's notifications.
func (s *Service) Get(ctx context.Context, userID, id int64) (Notification, error) {
	ns, err := s.query(ctx, `WHERE user_id = ? AND id = ?`, userID, id)
	if err != nil {
		return Notification{}, err
	}
	if len(ns) == 0 {
		return Notification{}, ErrNotFound
	}
	return ns[0], nil
}

// MarkSeen marks some of userID's notifications as shown; none = all.
func (s *Service) MarkSeen(ctx context.Context, userID int64, ids ...int64) error {
	q, args := `UPDATE notifications SET seen_at = ? WHERE user_id = ? AND seen_at IS NULL`, []any{store.FormatTime(s.now()), userID}
	if len(ids) > 0 {
		q += ` AND id IN (` + strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + `)`
		for _, id := range ids {
			args = append(args, id)
		}
	}
	if _, err := s.db.ExecContext(ctx, q, args...); err != nil {
		return fmt.Errorf("notify: mark seen: %w", err)
	}
	return nil
}

// Delete removes one of userID's notifications.
func (s *Service) Delete(ctx context.Context, userID, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notifications WHERE user_id = ? AND id = ?`, userID, id)
	if err != nil {
		return fmt.Errorf("notify: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteAll removes all of userID's notifications and returns how many.
func (s *Service) DeleteAll(ctx context.Context, userID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM notifications WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("notify: delete all: %w", err)
	}
	n, _ := res.RowsAffected()
	s.log.Info("notifications cleared", "user_id", userID, "count", n)
	return n, nil
}

// Describe is a notification in words: the kind's label, who caused it and
// the text, e.g. "Pages: from alice: would like to talk in #talk-alice".
func (s *Service) Describe(n Notification) string {
	label := n.Kind
	if k, ok := s.Kind(n.Kind); ok {
		label = k.Label
	}
	out := label
	if n.Actor != "" {
		out += ", from " + n.Actor
	}
	if n.Text != "" {
		out += ": " + n.Text
	}
	return out
}

// Age describes how long ago t was, e.g. "5 minutes ago".
func Age(t, now time.Time) string {
	d := now.Sub(t)
	n, unit := 0, ""
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		n, unit = int(d/time.Minute), "minute"
	case d < 48*time.Hour:
		n, unit = int(d/time.Hour), "hour"
	default:
		n, unit = int(d/(24*time.Hour)), "day"
	}
	if n != 1 {
		unit += "s"
	}
	return strconv.Itoa(n) + " " + unit + " ago"
}

// Now returns the service's clock, for Age.
func (s *Service) Now() time.Time { return s.now() }

// ExportSource is the notifications part of the data export.
func (s *Service) ExportSource() export.Source {
	return export.Source{Name: "notifications", Export: s.export}
}

func (s *Service) export(ctx context.Context, userID int64) ([]export.File, error) {
	ns, err := s.List(ctx, userID)
	if err != nil {
		return nil, err
	}
	settings, err := s.Settings(ctx, userID)
	if err != nil {
		return nil, err
	}
	type out struct {
		Kind    string    `json:"kind"`
		From    string    `json:"from,omitempty"`
		Text    string    `json:"text"`
		Created time.Time `json:"created"`
		Seen    bool      `json:"seen"`
	}
	list := []out{}
	for _, n := range ns {
		list = append(list, out{n.Kind, n.Actor, n.Text, n.Created, n.Seen})
	}
	f, err := export.JSON("notifications.json", map[string]any{"notifications": list, "settings": settings})
	return []export.File{f}, err
}

// RefPath returns a WebPath for kinds whose Ref is a row ID: prefix
// followed by the ID (e.g. "/m/12"), or "" if Ref is not a positive
// number.
func RefPath(prefix string) func(Notification) string {
	return func(n Notification) string {
		if id, err := strconv.ParseInt(n.Ref, 10, 64); err != nil || id <= 0 || strconv.FormatInt(id, 10) != n.Ref {
			return ""
		}
		return prefix + n.Ref
	}
}
