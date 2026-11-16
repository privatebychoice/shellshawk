// Package contacts is the core Contacts plugin (docs/DESIGN.md §12): each
// member's personal contact list and contact groups. Other plugins use it
// through the exported methods — Messages to address contact groups, the
// privacy rules to decide who is a "friend" (both members have each other as
// contacts).
package contacts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"go.privatebychoice.com/shellshawk/internal/events"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Limits.
const (
	MaxContacts    = 500
	MaxGroups      = 50
	MaxNoteLen     = 200
	MaxGroupName   = 32
	pluginVersion  = "1.0.0"
	contactsPlugin = "contacts"
)

// Errors.
var (
	ErrUnknownUser = errors.New("there is no active member with that username")
	ErrSelf        = errors.New("you cannot add yourself")
	ErrExists      = errors.New("already exists")
	ErrNotFound    = errors.New("not found")
	ErrLimit       = errors.New("limit reached")
	ErrInvalid     = errors.New("invalid value")
)

// Plugin implements plugin.Plugin.
type Plugin struct {
	h   *plugin.Host
	now func() time.Time
}

// New returns the Contacts plugin.
func New() *Plugin { return &Plugin{now: time.Now} }

var _ plugin.Plugin = (*Plugin)(nil)

// Manifest implements plugin.Plugin.
func (p *Plugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID: contactsPlugin, Name: "Contacts", Version: pluginVersion,
		Description: "Your personal contact list and contact groups",
		Migrations: []store.Migration{{Version: 1, Name: "contacts", SQL: `
			CREATE TABLE contacts_entries (
				owner_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
				contact_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
				note       TEXT    NOT NULL DEFAULT '',
				created_at TEXT    NOT NULL,
				PRIMARY KEY (owner_id, contact_id),
				CHECK (owner_id <> contact_id)
			) STRICT;
			CREATE INDEX contacts_entries_contact ON contacts_entries (contact_id);

			CREATE TABLE contacts_groups (
				id         INTEGER PRIMARY KEY,
				owner_id   INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
				name       TEXT    NOT NULL COLLATE NOCASE,
				created_at TEXT    NOT NULL,
				UNIQUE (owner_id, name)
			) STRICT;

			-- The composite key keeps group members a subset of the owner's
			-- contacts: removing a contact removes it from every group.
			CREATE TABLE contacts_group_members (
				group_id   INTEGER NOT NULL REFERENCES contacts_groups (id) ON DELETE CASCADE,
				owner_id   INTEGER NOT NULL,
				contact_id INTEGER NOT NULL,
				PRIMARY KEY (group_id, contact_id),
				FOREIGN KEY (owner_id, contact_id) REFERENCES contacts_entries (owner_id, contact_id) ON DELETE CASCADE
			) STRICT;`}},
		MenuItems: []plugin.MenuItem{{
			Key: "main", Label: "Contacts", Help: "Your contact list and contact groups", Run: p.run,
		}},
		Export: p.export,
	}
}

// Init implements plugin.Plugin.
func (p *Plugin) Init(_ context.Context, h *plugin.Host) error {
	p.h = h
	if h.Events != nil {
		h.Events.Subscribe(events.UserErased, "contacts", p.erase)
	}
	return nil
}

// Contact is an entry in a member's list.
type Contact struct {
	UserID   int64
	Username string
	Note     string
	Mutual   bool // they have the owner as a contact too ("friend")
	AddedAt  time.Time
}

// Group is a contact group.
type Group struct {
	ID      int64
	Name    string
	Members int
}

func cleanText(s string, max int, required bool) (string, error) {
	s = strings.TrimSpace(s)
	n := utf8.RuneCountInString(s)
	if (required && n == 0) || n > max || term.Sanitize(s, false) != s {
		if required {
			return "", fmt.Errorf("%w: must be 1 to %d printable characters", ErrInvalid, max)
		}
		return "", fmt.Errorf("%w: must be at most %d printable characters", ErrInvalid, max)
	}
	return s, nil
}

// Add adds username to owner's contacts.
func (p *Plugin) Add(ctx context.Context, owner int64, username, note string) error {
	note, err := cleanText(note, MaxNoteLen, false)
	if err != nil {
		return err
	}
	u, err := p.h.Auth.UserByUsername(ctx, username)
	if err != nil || u.Status != auth.StatusActive {
		return ErrUnknownUser
	}
	if u.ID == owner {
		return ErrSelf
	}
	return store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM contacts_entries WHERE owner_id = ?`, owner).Scan(&n); err != nil {
			return err
		}
		if n >= MaxContacts {
			return fmt.Errorf("%w: at most %d contacts", ErrLimit, MaxContacts)
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO contacts_entries (owner_id, contact_id, note, created_at) VALUES (?, ?, ?, ?)
			ON CONFLICT DO NOTHING`, owner, u.ID, note, store.FormatTime(p.now()))
		if err != nil {
			return fmt.Errorf("contacts: add: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%s is %w in your contacts", u.Username, ErrExists)
		}
		p.h.Log.Info("contact added", "owner", owner, "contact", u.ID)
		return nil
	})
}

// Remove removes a contact (and its group memberships).
func (p *Plugin) Remove(ctx context.Context, owner, contact int64) error {
	res, err := p.h.DB.ExecContext(ctx, `DELETE FROM contacts_entries WHERE owner_id = ? AND contact_id = ?`, owner, contact)
	if err != nil {
		return fmt.Errorf("contacts: remove: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	p.h.Log.Info("contact removed", "owner", owner, "contact", contact)
	return nil
}

// SetNote changes a contact's private note.
func (p *Plugin) SetNote(ctx context.Context, owner, contact int64, note string) error {
	note, err := cleanText(note, MaxNoteLen, false)
	if err != nil {
		return err
	}
	res, err := p.h.DB.ExecContext(ctx, `UPDATE contacts_entries SET note = ? WHERE owner_id = ? AND contact_id = ?`, note, owner, contact)
	if err != nil {
		return fmt.Errorf("contacts: note: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// list returns contacts matching an extra condition, sorted by username.
func (p *Plugin) list(ctx context.Context, owner int64, join, where string, args ...any) ([]Contact, error) {
	q := `SELECT e.contact_id, e.note, e.created_at,
			EXISTS (SELECT 1 FROM contacts_entries r WHERE r.owner_id = e.contact_id AND r.contact_id = e.owner_id)
		FROM contacts_entries e ` + join + ` WHERE e.owner_id = ? ` + where
	rows, err := p.h.DB.QueryContext(ctx, q, append([]any{owner}, args...)...)
	if err != nil {
		return nil, fmt.Errorf("contacts: list: %w", err)
	}
	defer rows.Close()
	var out []Contact
	var ids []int64
	for rows.Next() {
		var c Contact
		var added string
		if err := rows.Scan(&c.UserID, &c.Note, &added, &c.Mutual); err != nil {
			return nil, err
		}
		if c.AddedAt, err = store.ParseTime(added); err != nil {
			return nil, err
		}
		out = append(out, c)
		ids = append(ids, c.UserID)
	}
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
	slices.SortFunc(out, func(a, b Contact) int { return strings.Compare(a.Username, b.Username) })
	return out, nil
}

// List returns owner's contacts sorted by username.
func (p *Plugin) List(ctx context.Context, owner int64) ([]Contact, error) {
	return p.list(ctx, owner, "", "")
}

// IsContact reports whether other is in owner's contacts.
func (p *Plugin) IsContact(ctx context.Context, owner, other int64) (bool, error) {
	var ok bool
	err := p.h.DB.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM contacts_entries WHERE owner_id = ? AND contact_id = ?)`, owner, other).Scan(&ok)
	return ok, err
}

// IsFriend reports whether a and b have each other as contacts.
func (p *Plugin) IsFriend(ctx context.Context, a, b int64) (bool, error) {
	var n int
	err := p.h.DB.QueryRowContext(ctx, `SELECT count(*) FROM contacts_entries
		WHERE (owner_id = ? AND contact_id = ?) OR (owner_id = ? AND contact_id = ?)`, a, b, b, a).Scan(&n)
	return n == 2, err
}

// ---- groups -----------------------------------------------------------------

// Groups returns owner's contact groups sorted by name.
func (p *Plugin) Groups(ctx context.Context, owner int64) ([]Group, error) {
	rows, err := p.h.DB.QueryContext(ctx, `
		SELECT g.id, g.name, (SELECT count(*) FROM contacts_group_members m WHERE m.group_id = g.id)
		FROM contacts_groups g WHERE g.owner_id = ? ORDER BY g.name`, owner)
	if err != nil {
		return nil, fmt.Errorf("contacts: groups: %w", err)
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Members); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// CreateGroup creates a contact group.
func (p *Plugin) CreateGroup(ctx context.Context, owner int64, name string) (int64, error) {
	name, err := cleanText(name, MaxGroupName, true)
	if err != nil {
		return 0, err
	}
	if strings.Contains(name, ",") {
		return 0, fmt.Errorf("%w: group names cannot contain commas", ErrInvalid)
	}
	var id int64
	err = store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM contacts_groups WHERE owner_id = ?`, owner).Scan(&n); err != nil {
			return err
		}
		if n >= MaxGroups {
			return fmt.Errorf("%w: at most %d groups", ErrLimit, MaxGroups)
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO contacts_groups (owner_id, name, created_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING`,
			owner, name, store.FormatTime(p.now()))
		if err != nil {
			return fmt.Errorf("contacts: create group: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("a group with that name %w", ErrExists)
		}
		id, _ = res.LastInsertId()
		return nil
	})
	return id, err
}

// DeleteGroup deletes one of owner's groups (not the contacts in it).
func (p *Plugin) DeleteGroup(ctx context.Context, owner, group int64) error {
	res, err := p.h.DB.ExecContext(ctx, `DELETE FROM contacts_groups WHERE id = ? AND owner_id = ?`, group, owner)
	if err != nil {
		return fmt.Errorf("contacts: delete group: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AddToGroup puts one of owner's contacts into one of owner's groups.
func (p *Plugin) AddToGroup(ctx context.Context, owner, group, contact int64) error {
	res, err := p.h.DB.ExecContext(ctx, `
		INSERT INTO contacts_group_members (group_id, owner_id, contact_id)
		SELECT g.id, g.owner_id, e.contact_id FROM contacts_groups g
		JOIN contacts_entries e ON e.owner_id = g.owner_id AND e.contact_id = ?
		WHERE g.id = ? AND g.owner_id = ?
		ON CONFLICT DO NOTHING`, contact, group, owner)
	if err != nil {
		return fmt.Errorf("contacts: add to group: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveFromGroup takes a contact out of a group.
func (p *Plugin) RemoveFromGroup(ctx context.Context, owner, group, contact int64) error {
	res, err := p.h.DB.ExecContext(ctx, `DELETE FROM contacts_group_members WHERE group_id = ? AND owner_id = ? AND contact_id = ?`, group, owner, contact)
	if err != nil {
		return fmt.Errorf("contacts: remove from group: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// GroupMembers returns the contacts in one of owner's groups.
func (p *Plugin) GroupMembers(ctx context.Context, owner, group int64) ([]Contact, error) {
	return p.list(ctx, owner, "JOIN contacts_group_members m ON m.owner_id = e.owner_id AND m.contact_id = e.contact_id", "AND m.group_id = ?", group)
}

// GroupMemberIDs returns the account IDs in owner's group called name
// (case-insensitive), for addressing messages.
func (p *Plugin) GroupMemberIDs(ctx context.Context, owner int64, name string) ([]int64, error) {
	var id int64
	err := p.h.DB.QueryRowContext(ctx, `SELECT id FROM contacts_groups WHERE owner_id = ? AND name = ?`, owner, strings.TrimSpace(name)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("contact group %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	members, err := p.GroupMembers(ctx, owner, id)
	if err != nil {
		return nil, err
	}
	ids := make([]int64, len(members))
	for i, m := range members {
		ids[i] = m.UserID
	}
	return ids, nil
}
