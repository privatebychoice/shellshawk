// Package motd is the Message of the Day plugin: members holding
// motd.edit (moderators by default; administrators always) set a markdown
// message that each member sees once after logging in, until it changes.
// It can be read again from the menu, and is shown on the web home page.
package motd

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// PermEdit lets a member set or clear the message of the day.
const PermEdit = "motd.edit"

// MaxBody is the longest message, in characters.
const MaxBody = 4000

// ErrInvalid reports an unacceptable message.
var ErrInvalid = errors.New("invalid message of the day")

// Plugin implements plugin.Plugin.
type Plugin struct {
	h   *plugin.Host
	now func() time.Time
}

// New returns the MOTD plugin.
func New() *Plugin { return &Plugin{now: time.Now} }

var _ plugin.Plugin = (*Plugin)(nil)

// Manifest implements plugin.Plugin.
func (p *Plugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID: "motd", Name: "Message of the day", Version: "1.0.0",
		Description: "A message shown to members after they log in",
		Permissions: []plugin.Permission{
			{Name: PermEdit, Description: "Set the message of the day", DefaultGroups: []string{perm.GroupModerator}},
		},
		Migrations: []store.Migration{{Version: 1, Name: "motd", SQL: `
			-- The single current message (id 1). version increases with every
			-- change, including clearing it (body ''), so members see each
			-- new message once.
			CREATE TABLE motd_message (
				id         INTEGER PRIMARY KEY CHECK (id = 1),
				body       TEXT    NOT NULL,
				version    INTEGER NOT NULL,
				updated_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
				updated_at TEXT    NOT NULL
			) STRICT;

			-- The last version each member was shown after logging in.
			CREATE TABLE motd_seen (
				user_id INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
				version INTEGER NOT NULL
			) STRICT;`}},
		MenuItems: []plugin.MenuItem{{Key: "main", Label: "Message of the day", Help: "Read the message of the day", Run: p.run}},
		OnLogin:   p.onLogin,
		WebHome:   p.webHome,
		Export:    p.export,
	}
}

// Init implements plugin.Plugin.
func (p *Plugin) Init(_ context.Context, h *plugin.Host) error {
	p.h = h
	if h.Events != nil {
		h.Events.Subscribe(events.UserErased, "motd", p.erase)
	}
	return nil
}

// Message is the current message of the day. Body is "" when there is none.
type Message struct {
	Body      string
	Version   int64
	UpdatedBy string // username, or "" if unknown
	UpdatedAt time.Time
}

// Get returns the current message.
func (p *Plugin) Get(ctx context.Context) (Message, error) {
	var m Message
	var by sql.NullInt64
	var at string
	err := p.h.DB.QueryRowContext(ctx, `SELECT body, version, updated_by, updated_at FROM motd_message WHERE id = 1`).
		Scan(&m.Body, &m.Version, &by, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return Message{}, nil
	}
	if err != nil {
		return Message{}, fmt.Errorf("motd: get: %w", err)
	}
	if m.UpdatedAt, err = store.ParseTime(at); err != nil {
		return Message{}, err
	}
	if by.Valid {
		names, err := p.h.Auth.Usernames(ctx, []int64{by.Int64})
		if err != nil {
			return Message{}, err
		}
		m.UpdatedBy = names[by.Int64]
	}
	return m, nil
}

// Set replaces the message (motd.edit). An empty body clears it.
func (p *Plugin) Set(ctx context.Context, actor int64, body string) error {
	if err := p.h.Perms.Require(ctx, actor, PermEdit); err != nil {
		return err
	}
	body = strings.TrimRight(body, " \n\t")
	if utf8.RuneCountInString(body) > MaxBody {
		return fmt.Errorf("%w: at most %d characters", ErrInvalid, MaxBody)
	}
	if !utf8.ValidString(body) || term.Sanitize(body, true) != strings.ReplaceAll(body, "\t", " ") {
		return fmt.Errorf("%w: it contains control characters", ErrInvalid)
	}
	if _, err := p.h.DB.ExecContext(ctx, `INSERT INTO motd_message (id, body, version, updated_by, updated_at) VALUES (1, ?, 1, ?, ?)
		ON CONFLICT (id) DO UPDATE SET body = excluded.body, version = version + 1,
			updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
		body, actor, store.FormatTime(p.now())); err != nil {
		return fmt.Errorf("motd: set: %w", err)
	}
	p.h.Log.Info("message of the day changed", "actor", actor, "cleared", body == "")
	return nil
}

// Unseen returns the message if user has not been shown this version yet.
func (p *Plugin) Unseen(ctx context.Context, user int64) (Message, bool, error) {
	m, err := p.Get(ctx)
	if err != nil || m.Body == "" {
		return Message{}, false, err
	}
	var seen int64
	err = p.h.DB.QueryRowContext(ctx, `SELECT version FROM motd_seen WHERE user_id = ?`, user).Scan(&seen)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Message{}, false, fmt.Errorf("motd: seen: %w", err)
	}
	return m, seen < m.Version, nil
}

// MarkSeen records that user has been shown version.
func (p *Plugin) MarkSeen(ctx context.Context, user, version int64) error {
	_, err := p.h.DB.ExecContext(ctx, `INSERT INTO motd_seen (user_id, version) VALUES (?, ?)
		ON CONFLICT (user_id) DO UPDATE SET version = max(version, excluded.version)`, user, version)
	if err != nil {
		return fmt.Errorf("motd: mark seen: %w", err)
	}
	return nil
}

// page renders the message for the TUI.
func (p *Plugin) page(s plugin.Session, m Message) tui.Page {
	src := m.Body + "\n\n---\n\n*Updated " + m.UpdatedAt.UTC().Format("2006-01-02 15:04 UTC")
	if m.UpdatedBy != "" {
		src += " by " + m.UpdatedBy
	}
	return s.Markdown(s.Title("Message of the day"), src+".*")
}

// onLogin shows a new or changed message once, after login.
func (p *Plugin) onLogin(ctx context.Context, s plugin.Session) error {
	m, unseen, err := p.Unseen(ctx, s.UserID())
	if err != nil || !unseen {
		return err
	}
	showErr := s.UI().Show(ctx, p.page(s, m))
	if showErr != nil && !errors.Is(showErr, tui.ErrCancelled) {
		return showErr // e.g. the connection closed: show it next time
	}
	return p.MarkSeen(ctx, s.UserID(), m.Version)
}

// erase forgets an erased member: what they have seen, and their name on
// the message they last set.
func (p *Plugin) erase(ctx context.Context, e events.Event) error {
	if _, err := p.h.DB.ExecContext(ctx, `DELETE FROM motd_seen WHERE user_id = ?`, e.UserID); err != nil {
		return err
	}
	_, err := p.h.DB.ExecContext(ctx, `UPDATE motd_message SET updated_by = NULL WHERE updated_by = ?`, e.UserID)
	return err
}

// export returns what the plugin stores about a member (right of access).
func (p *Plugin) export(ctx context.Context, user int64) ([]export.File, error) {
	out := map[string]any{}
	var seen int64
	switch err := p.h.DB.QueryRowContext(ctx, `SELECT version FROM motd_seen WHERE user_id = ?`, user).Scan(&seen); {
	case err == nil:
		out["last_version_seen"] = seen
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	var body, at string
	switch err := p.h.DB.QueryRowContext(ctx, `SELECT body, updated_at FROM motd_message WHERE id = 1 AND updated_by = ?`, user).Scan(&body, &at); {
	case err == nil:
		out["current_message_set_by_you"] = map[string]string{"body": body, "updated_at": at}
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	f, err := export.JSON("motd.json", out)
	return []export.File{f}, err
}
