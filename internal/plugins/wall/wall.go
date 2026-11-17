// Package wall is the Wall plugin: each member may write one line, shown to
// all members, with **bold** and *italic* emphasis. A line expires a set
// time after its last edit (an administrator setting, default 7 days) and
// is then deleted.
package wall

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Permissions.
const (
	PermWrite    = "wall.write"    // write and edit one's own line
	PermModerate = "wall.moderate" // remove other members' lines
)

// Limits and defaults.
const (
	MaxLine            = 200 // characters, including emphasis markers
	DefaultExpiryHours = 7 * 24
	MaxExpiryHours     = 365 * 24
	setExpiryHours     = "expiry_hours"
	purgeEvery         = time.Hour
	pluginVersion      = "1.0.0"
)

// Errors.
var (
	ErrNotFound = errors.New("there is no wall line")
	ErrInvalid  = errors.New("invalid wall line")
)

// Plugin implements plugin.Plugin.
type Plugin struct {
	h   *plugin.Host
	now func() time.Time
}

// New returns the Wall plugin.
func New() *Plugin { return &Plugin{now: time.Now} }

var _ plugin.Plugin = (*Plugin)(nil)

// Manifest implements plugin.Plugin.
func (p *Plugin) Manifest() plugin.Manifest {
	everyone := []string{perm.GroupMember, perm.GroupModerator}
	return plugin.Manifest{
		ID: "wall", Name: "Wall", Version: pluginVersion,
		Description: "One line per member, shown to everyone for a limited time",
		Permissions: []plugin.Permission{
			{Name: PermWrite, Description: "Write a line on the wall", DefaultGroups: everyone},
			{Name: PermModerate, Description: "Remove other members' wall lines", DefaultGroups: []string{perm.GroupModerator}},
		},
		Settings: []plugin.Setting{{
			Field: form.Field{Name: setExpiryHours, Label: "Hours before a wall line expires",
				Help: "Counted from the line's last edit; editing renews it. Expired lines are deleted.",
				Kind: form.SingleLine, Subtype: form.Int, Required: true, Min: form.Bound(1), Max: form.Bound(MaxExpiryHours)},
			Default: strconv.Itoa(DefaultExpiryHours),
		}},
		Migrations: []store.Migration{{Version: 1, Name: "wall", SQL: `
			-- One line per member; updated_at starts the expiry clock.
			CREATE TABLE wall_entries (
				user_id    INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
				text       TEXT    NOT NULL,
				updated_at TEXT    NOT NULL
			) STRICT;
			CREATE INDEX wall_entries_updated ON wall_entries (updated_at);`}},
		MenuItems: []plugin.MenuItem{{Key: "main", Label: "Wall", Help: "One line from each member", Run: p.run}},
		Web:       p.webRoutes(),
		Export:    p.export,
	}
}

// Init implements plugin.Plugin. It deletes expired lines at startup and
// then hourly, until ctx ends.
func (p *Plugin) Init(ctx context.Context, h *plugin.Host) error {
	p.h = h
	if h.Events != nil {
		h.Events.Subscribe(events.UserErased, "wall", p.erase)
	}
	purge := func() {
		if n, err := p.PurgeExpired(ctx); err != nil && ctx.Err() == nil {
			h.Log.Error("wall purge failed", "err", err)
		} else if n > 0 {
			h.Log.Info("expired wall lines deleted", "lines", n)
		}
	}
	purge()
	go func() {
		t := time.NewTicker(purgeEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				purge()
			}
		}
	}()
	return nil
}

// Expiry is how long a line stays on the wall after its last edit.
func (p *Plugin) Expiry(ctx context.Context) time.Duration {
	h := DefaultExpiryHours
	if v, err := p.h.Settings.Get(ctx, setExpiryHours); err == nil {
		if n, err := strconv.Atoi(v); err == nil {
			h = n
		}
	}
	return time.Duration(h) * time.Hour
}

// Entry is one member's wall line.
type Entry struct {
	UserID    int64
	Username  string
	Text      string // as typed, with emphasis markers
	UpdatedAt time.Time
	ExpiresAt time.Time
}

// clean checks a line: one line of printable text, 1 to MaxLine characters.
func clean(text string) (string, error) {
	text = strings.TrimSpace(text)
	switch {
	case text == "":
		return "", fmt.Errorf("%w: write something, or remove your line instead", ErrInvalid)
	case utf8.RuneCountInString(text) > MaxLine:
		return "", fmt.Errorf("%w: at most %d characters", ErrInvalid, MaxLine)
	case term.Sanitize(text, false) != text:
		return "", fmt.Errorf("%w: one line of printable text only", ErrInvalid)
	case Plain(text) == "":
		return "", fmt.Errorf("%w: the line has no text, only emphasis markers", ErrInvalid)
	}
	return text, nil
}

// Set writes or replaces user's line, restarting its expiry.
func (p *Plugin) Set(ctx context.Context, user int64, text string) error {
	if err := p.h.Perms.Require(ctx, user, PermWrite); err != nil {
		return err
	}
	text, err := clean(text)
	if err != nil {
		return err
	}
	if _, err := p.h.DB.ExecContext(ctx, `INSERT INTO wall_entries (user_id, text, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET text = excluded.text, updated_at = excluded.updated_at`,
		user, text, store.FormatTime(p.now())); err != nil {
		return fmt.Errorf("wall: set: %w", err)
	}
	p.h.Log.Info("wall line set", "user_id", user)
	return nil
}

// Remove deletes owner's line. Members may remove their own; removing
// someone else's needs wall.moderate.
func (p *Plugin) Remove(ctx context.Context, actor, owner int64) error {
	if actor != owner {
		if err := p.h.Perms.Require(ctx, actor, PermModerate); err != nil {
			return err
		}
	}
	res, err := p.h.DB.ExecContext(ctx, `DELETE FROM wall_entries WHERE user_id = ?`, owner)
	if err != nil {
		return fmt.Errorf("wall: remove: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	p.h.Log.Info("wall line removed", "owner", owner, "actor", actor)
	return nil
}

// Entries returns the lines that have not expired, newest first.
func (p *Plugin) Entries(ctx context.Context) ([]Entry, error) {
	exp := p.Expiry(ctx)
	rows, err := p.h.DB.QueryContext(ctx, `SELECT user_id, text, updated_at FROM wall_entries
		WHERE updated_at >= ? ORDER BY updated_at DESC, user_id`, store.FormatTime(p.now().Add(-exp)))
	if err != nil {
		return nil, fmt.Errorf("wall: list: %w", err)
	}
	var out []Entry
	var ids []int64
	for rows.Next() {
		var e Entry
		var at string
		if err := rows.Scan(&e.UserID, &e.Text, &at); err != nil {
			rows.Close()
			return nil, err
		}
		if e.UpdatedAt, err = store.ParseTime(at); err != nil {
			rows.Close()
			return nil, err
		}
		e.ExpiresAt = e.UpdatedAt.Add(exp)
		out = append(out, e)
		ids = append(ids, e.UserID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	names, err := p.h.Auth.Usernames(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Username = names[out[i].UserID]
	}
	return out, nil
}

// Mine returns user's line, if they have one that has not expired.
func (p *Plugin) Mine(ctx context.Context, user int64) (Entry, bool, error) {
	all, err := p.Entries(ctx)
	if err != nil {
		return Entry{}, false, err
	}
	for _, e := range all {
		if e.UserID == user {
			return e, true, nil
		}
	}
	return Entry{}, false, nil
}

// PurgeExpired deletes lines past their expiry.
func (p *Plugin) PurgeExpired(ctx context.Context) (int64, error) {
	res, err := p.h.DB.ExecContext(ctx, `DELETE FROM wall_entries WHERE updated_at < ?`, store.FormatTime(p.now().Add(-p.Expiry(ctx))))
	if err != nil {
		return 0, fmt.Errorf("wall: purge: %w", err)
	}
	return res.RowsAffected()
}

// erase deletes an erased member's line.
func (p *Plugin) erase(ctx context.Context, e events.Event) error {
	_, err := p.h.DB.ExecContext(ctx, `DELETE FROM wall_entries WHERE user_id = ?`, e.UserID)
	return err
}

// export returns the member's wall line, if any (right of access).
func (p *Plugin) export(ctx context.Context, user int64) ([]export.File, error) {
	type lineOut struct {
		Text      string    `json:"text"`
		UpdatedAt time.Time `json:"updated_at"`
	}
	var out []lineOut
	var text, at string
	err := p.h.DB.QueryRowContext(ctx, `SELECT text, updated_at FROM wall_entries WHERE user_id = ?`, user).Scan(&text, &at)
	switch {
	case err == nil:
		t, perr := store.ParseTime(at)
		if perr != nil {
			return nil, perr
		}
		out = append(out, lineOut{Text: text, UpdatedAt: t})
	case !errors.Is(err, sql.ErrNoRows):
		return nil, err
	}
	f, err := export.JSON("wall.json", out)
	return []export.File{f}, err
}

// Find returns the current lines of members whose username starts with
// query (case-insensitive; a leading @ is ignored).
func (p *Plugin) Find(ctx context.Context, query string) ([]Entry, error) {
	q := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(query), "@"))
	if q == "" {
		return nil, fmt.Errorf("%w: type a username, or the start of one", ErrInvalid)
	}
	all, err := p.Entries(ctx)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range all {
		if strings.HasPrefix(strings.ToLower(e.Username), q) {
			out = append(out, e)
		}
	}
	return out, nil
}

// Access is which groups may write on the wall and which may remove any
// line: the groups holding wall.write and wall.moderate. Groups holding
// core.admin are left out, since administrators can always do both.
type Access struct {
	Groups          []perm.Group // the groups that can be chosen
	Write, Moderate map[int64]bool
}

// Access returns the current wall access.
func (p *Plugin) Access(ctx context.Context) (Access, error) {
	groups, err := p.h.Perms.Groups(ctx)
	if err != nil {
		return Access{}, err
	}
	a := Access{Write: map[int64]bool{}, Moderate: map[int64]bool{}}
	for _, g := range groups {
		held := map[string]bool{}
		for _, pm := range g.Permissions {
			held[pm] = true
		}
		if held[perm.Admin] {
			continue
		}
		a.Groups = append(a.Groups, g)
		a.Write[g.ID], a.Moderate[g.ID] = held[PermWrite], held[PermModerate]
	}
	return a, nil
}

// SetAccess makes exactly the given groups able to write on the wall and
// to remove any line (administrators only). Changes go through the group
// permissions, so they are audited and shown on the Groups page too.
func (p *Plugin) SetAccess(ctx context.Context, actor int64, write, moderate []int64) error {
	if err := p.h.Perms.Require(ctx, actor, perm.Admin); err != nil {
		return err
	}
	cur, err := p.Access(ctx)
	if err != nil {
		return err
	}
	want := func(ids []int64) (map[int64]bool, error) {
		m := map[int64]bool{}
		for _, id := range ids {
			if _, ok := cur.Write[id]; !ok {
				return nil, fmt.Errorf("%w: group %d cannot be chosen", ErrInvalid, id)
			}
			m[id] = true
		}
		return m, nil
	}
	w, err := want(write)
	if err != nil {
		return err
	}
	m, err := want(moderate)
	if err != nil {
		return err
	}
	for _, g := range cur.Groups {
		for _, c := range []struct {
			perm      string
			have, set bool
		}{{PermWrite, cur.Write[g.ID], w[g.ID]}, {PermModerate, cur.Moderate[g.ID], m[g.ID]}} {
			switch {
			case c.set && !c.have:
				err = p.h.Perms.Grant(ctx, actor, g.ID, c.perm)
			case !c.set && c.have:
				err = p.h.Perms.Revoke(ctx, actor, g.ID, c.perm)
			}
			if err != nil {
				return fmt.Errorf("wall: %s for group %s: %w", c.perm, g.Name, err)
			}
		}
	}
	p.h.Log.Info("wall access changed", "actor", actor, "write_groups", len(w), "moderate_groups", len(m))
	return nil
}
