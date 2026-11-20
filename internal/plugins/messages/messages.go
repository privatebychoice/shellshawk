// Package messages is the core Messages plugin (docs/DESIGN.md §12): private
// mail between members with subjects, markdown bodies and replies, per-member
// unread/read/deleted counts, and read-only SFTP access to one's mail.
package messages

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"go.privatebychoice.com/shellshawk/internal/events"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/contacts"
	"go.privatebychoice.com/shellshawk/internal/privacy"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// PermSend allows sending messages. Granted to "member" on first load.
const PermSend = "messages.send"

// Fixed limits.
const (
	MaxSubject = 120
	ListLimit  = 200 // messages shown per folder
)

// Setting keys.
const (
	setMaxRecipients = "max_recipients"
	setMaxPerHour    = "max_per_hour"
	setMaxBody       = "max_body"
	setDeletedDays   = "deleted_days"
)

// DefaultDeletedDays is how long messages stay in a Deleted folder before
// they are removed permanently, unless an administrator changes it.
const DefaultDeletedDays = 30

// purgeEvery is how often deleted messages past their time are removed.
const purgeEvery = time.Hour

// Errors.
var (
	ErrNotFound   = errors.New("message not found")
	ErrInvalid    = errors.New("invalid message")
	ErrRateLimit  = errors.New("you have sent too many messages in the last hour; please wait")
	ErrNoneToSend = errors.New("add at least one recipient")
)

// RecipientError lists recipients that could not be resolved, or that do
// not accept private messages from the sender.
type RecipientError struct {
	Unknown []string
	Refused []string
}

func (e *RecipientError) Error() string {
	var parts []string
	if len(e.Unknown) > 0 {
		parts = append(parts, "unknown recipient(s): "+strings.Join(e.Unknown, ", "))
	}
	if len(e.Refused) > 0 {
		parts = append(parts, "not accepting messages from you: "+strings.Join(e.Refused, ", "))
	}
	return strings.Join(parts, "; ")
}

// Plugin implements plugin.Plugin.
type Plugin struct {
	h        *plugin.Host
	contacts *contacts.Plugin
	now      func() time.Time
}

// New returns the Messages plugin. It addresses contact groups through c.
func New(c *contacts.Plugin) *Plugin { return &Plugin{contacts: c, now: time.Now} }

var _ plugin.Plugin = (*Plugin)(nil)

// Manifest implements plugin.Plugin.
func (p *Plugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID: "messages", Name: "Messages", Version: "1.0.0",
		Description: "Private messages between members",
		Permissions: []plugin.Permission{{Name: PermSend, Description: "Send private messages", DefaultGroups: []string{perm.GroupMember, perm.GroupModerator}}},
		Settings: []plugin.Setting{
			{Field: form.Field{Name: setMaxRecipients, Label: "Maximum recipients per message", Kind: form.SingleLine, Subtype: form.Int,
				Required: true, Min: form.Bound(1), Max: form.Bound(100)}, Default: "20"},
			{Field: form.Field{Name: setMaxPerHour, Label: "Maximum messages a member can send per hour", Kind: form.SingleLine, Subtype: form.Int,
				Required: true, Min: form.Bound(1), Max: form.Bound(1000)}, Default: "30"},
			{Field: form.Field{Name: setMaxBody, Label: "Maximum message length (characters)", Kind: form.SingleLine, Subtype: form.Int,
				Required: true, Min: form.Bound(100), Max: form.Bound(50000)}, Default: "20000"},
			{Field: form.Field{Name: setDeletedDays, Label: "Days to keep messages in members' Deleted folders",
				Help: "After this many days a deleted message is removed permanently. Members can also remove them sooner themselves.",
				Kind: form.SingleLine, Subtype: form.Int, Required: true, Min: form.Bound(1), Max: form.Bound(3650)},
				Default: strconv.Itoa(DefaultDeletedDays)},
		},
		Migrations: []store.Migration{{Version: 1, Name: "messages", SQL: `
			-- sender_id becomes NULL if the sender's account is deleted;
			-- erasure (stage 9) handles anonymisation explicitly.
			CREATE TABLE messages_messages (
				id                INTEGER PRIMARY KEY,
				sender_id         INTEGER REFERENCES users (id) ON DELETE SET NULL,
				subject           TEXT    NOT NULL,
				body              TEXT    NOT NULL,
				parent_id         INTEGER REFERENCES messages_messages (id) ON DELETE SET NULL,
				created_at        TEXT    NOT NULL,
				sender_deleted_at TEXT
			) STRICT;
			CREATE INDEX messages_messages_sender ON messages_messages (sender_id, created_at);

			CREATE TABLE messages_recipients (
				message_id INTEGER NOT NULL REFERENCES messages_messages (id) ON DELETE CASCADE,
				user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
				read_at    TEXT,
				deleted_at TEXT,
				PRIMARY KEY (message_id, user_id)
			) STRICT;
			CREATE INDEX messages_recipients_user ON messages_recipients (user_id, deleted_at, read_at);`}},
		MenuItems:     []plugin.MenuItem{{Key: "main", Label: "Messages", Help: "Your private messages", Run: p.run, WebPath: "/"}},
		SFTP:          []sftpd.Mount{{Name: "messages", FS: &mailFS{p: p}}},
		Export:        p.export,
		Web:           p.webRoutes(),
		Notifications: p.notificationKinds(),
	}
}

// Init implements plugin.Plugin.
// Init implements plugin.Plugin. It starts the hourly removal of deleted
// messages past their time, which runs until ctx ends.
func (p *Plugin) Init(ctx context.Context, h *plugin.Host) error {
	p.h = h
	if h.Events != nil {
		h.Events.Subscribe(events.UserErased, "messages", p.erase)
	}
	purge := func() {
		if copies, texts, err := p.PurgeDeleted(ctx); err != nil && ctx.Err() == nil {
			h.Log.Error("deleted message purge failed", "err", err)
		} else if copies > 0 || texts > 0 {
			h.Log.Info("deleted messages purged", "copies", copies, "messages", texts)
		}
	}
	purge() // at startup, before anything else uses the plugin
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

// DeletedDays is how many days messages stay in Deleted folders.
func (p *Plugin) DeletedDays(ctx context.Context) int {
	n, err := p.setting(ctx, setDeletedDays)
	if err != nil {
		return DefaultDeletedDays
	}
	return n
}

func (p *Plugin) setting(ctx context.Context, key string) (int, error) {
	v, err := p.h.Settings.Get(ctx, key)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(v)
}

// Draft is a message to send.
type Draft struct {
	To            string // usernames, comma-separated
	ContactGroups []string
	Subject       string
	Body          string
	ParentID      int64 // message being replied to, or 0
}

// MaxBody returns the configured body length limit.
func (p *Plugin) MaxBody(ctx context.Context) int {
	n, err := p.setting(ctx, setMaxBody)
	if err != nil {
		return 20000
	}
	return n
}

// Send delivers a message and returns its ID.
func (p *Plugin) Send(ctx context.Context, from int64, d Draft) (int64, error) {
	if err := p.h.Perms.Require(ctx, from, PermSend); err != nil {
		return 0, err
	}
	subject := strings.TrimSpace(d.Subject)
	if n := utf8.RuneCountInString(subject); n == 0 || n > MaxSubject || term.Sanitize(subject, false) != subject {
		return 0, fmt.Errorf("%w: the subject must be 1 to %d printable characters", ErrInvalid, MaxSubject)
	}
	body := strings.TrimRight(d.Body, " \n\t")
	maxBody := p.MaxBody(ctx)
	if n := utf8.RuneCountInString(body); n == 0 || n > maxBody {
		return 0, fmt.Errorf("%w: the message must be 1 to %d characters", ErrInvalid, maxBody)
	}
	if !utf8.ValidString(body) || term.Sanitize(body, true) != strings.ReplaceAll(body, "\t", " ") {
		return 0, fmt.Errorf("%w: the message contains control characters", ErrInvalid)
	}

	to, err := p.resolve(ctx, from, d)
	if err != nil {
		return 0, err
	}
	maxTo, err := p.setting(ctx, setMaxRecipients)
	if err != nil {
		return 0, err
	}
	if len(to) > maxTo {
		return 0, fmt.Errorf("%w: at most %d recipients", ErrInvalid, maxTo)
	}
	perHour, err := p.setting(ctx, setMaxPerHour)
	if err != nil {
		return 0, err
	}

	var id int64
	err = store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		now := p.now()
		var sent int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM messages_messages WHERE sender_id = ? AND created_at > ?`,
			from, store.FormatTime(now.Add(-time.Hour))).Scan(&sent); err != nil {
			return err
		}
		if sent >= perHour {
			return ErrRateLimit
		}
		var parent any
		if d.ParentID != 0 {
			if _, err := p.access(ctx, tx, from, d.ParentID); err != nil {
				return err
			}
			parent = d.ParentID
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO messages_messages (sender_id, subject, body, parent_id, created_at) VALUES (?, ?, ?, ?, ?)`,
			from, subject, body, parent, store.FormatTime(now))
		if err != nil {
			return fmt.Errorf("messages: send: %w", err)
		}
		id, _ = res.LastInsertId()
		for _, uid := range to {
			if _, err := tx.ExecContext(ctx, `INSERT INTO messages_recipients (message_id, user_id) VALUES (?, ?)`, id, uid); err != nil {
				return fmt.Errorf("messages: deliver: %w", err)
			}
		}
		return nil
	})
	if err == nil {
		p.h.Log.Info("message sent", "from", from, "recipients", len(to), "message_id", id)
		p.notifyRecipients(ctx, from, id, subject, to)
	}
	return id, err
}

// resolve turns usernames and contact group names into active account IDs
// (the sender may include themselves, e.g. for a note to self), and checks
// each recipient's "who can send you
// private messages" setting (docs/DESIGN.md §5.1).
func (p *Plugin) resolve(ctx context.Context, from int64, d Draft) ([]int64, error) {
	var ids []int64
	var unknown []string
	for _, name := range strings.Split(d.To, ",") {
		name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "@"))
		if name == "" {
			continue
		}
		u, err := p.h.Auth.UserByUsername(ctx, name)
		if err != nil || u.Status != auth.StatusActive {
			unknown = append(unknown, name)
			continue
		}
		ids = append(ids, u.ID)
	}
	for _, g := range d.ContactGroups {
		members, err := p.contacts.GroupMemberIDs(ctx, from, g)
		if err != nil {
			unknown = append(unknown, "group "+g)
			continue
		}
		ids = append(ids, members...)
	}
	if len(unknown) > 0 {
		return nil, &RecipientError{Unknown: unknown}
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) == 0 {
		return nil, ErrNoneToSend
	}
	if p.h.Privacy != nil {
		names, err := p.h.Auth.Usernames(ctx, ids)
		if err != nil {
			return nil, err
		}
		var refused []string
		for _, id := range ids {
			ok, err := p.h.Privacy.Allows(ctx, from, id, privacy.Messages)
			if err != nil {
				return nil, err
			}
			if !ok {
				refused = append(refused, names[id])
			}
		}
		if len(refused) > 0 {
			slices.Sort(refused)
			return nil, &RecipientError{Refused: refused}
		}
	}
	return ids, nil
}

// Role is how a member relates to a message.
type Role int

const (
	RoleRecipient Role = iota + 1
	RoleSender
)

// access reports how user may see message id, or ErrNotFound. Deleted
// copies are still accessible (for the Deleted folder).
func (p *Plugin) access(ctx context.Context, db store.DBTX, user, id int64) (Role, error) {
	var isRecipient, isSender bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (SELECT 1 FROM messages_recipients WHERE message_id = ? AND user_id = ?),
		       EXISTS (SELECT 1 FROM messages_messages WHERE id = ? AND sender_id = ? AND sender_deleted_at IS NULL)`,
		id, user, id, user).Scan(&isRecipient, &isSender)
	switch {
	case err != nil:
		return 0, err
	case isRecipient:
		return RoleRecipient, nil
	case isSender:
		return RoleSender, nil
	}
	return 0, ErrNotFound
}

// Summary is a message in a folder listing.
type Summary struct {
	ID        int64
	From      string   // sender username ("former member" if gone)
	To        []string // recipient usernames (Sent folder only)
	Subject   string
	CreatedAt time.Time
	Read      bool
}

// Folder names.
const (
	Inbox   = "inbox"
	Sent    = "sent"
	Deleted = "deleted"
)

// List returns a folder's messages, newest first.
func (p *Plugin) List(ctx context.Context, user int64, folder string) ([]Summary, error) {
	var q string
	switch folder {
	case Inbox:
		q = `SELECT m.id, m.sender_id, m.subject, m.created_at, r.read_at IS NOT NULL
			FROM messages_recipients r JOIN messages_messages m ON m.id = r.message_id
			WHERE r.user_id = ? AND r.deleted_at IS NULL ORDER BY m.created_at DESC, m.id DESC LIMIT ?`
	case Deleted:
		q = `SELECT m.id, m.sender_id, m.subject, m.created_at, r.read_at IS NOT NULL
			FROM messages_recipients r JOIN messages_messages m ON m.id = r.message_id
			WHERE r.user_id = ? AND r.deleted_at IS NOT NULL ORDER BY r.deleted_at DESC, m.id DESC LIMIT ?`
	case Sent:
		q = `SELECT m.id, m.sender_id, m.subject, m.created_at, 1
			FROM messages_messages m WHERE m.sender_id = ? AND m.sender_deleted_at IS NULL
			ORDER BY m.created_at DESC, m.id DESC LIMIT ?`
	default:
		return nil, fmt.Errorf("messages: unknown folder %q", folder)
	}
	rows, err := p.h.DB.QueryContext(ctx, q, user, ListLimit)
	if err != nil {
		return nil, fmt.Errorf("messages: list: %w", err)
	}
	var out []Summary
	var senders []int64
	for rows.Next() {
		var s Summary
		var sender sql.NullInt64
		var created string
		if err := rows.Scan(&s.ID, &sender, &s.Subject, &created, &s.Read); err != nil {
			rows.Close()
			return nil, err
		}
		if s.CreatedAt, err = store.ParseTime(created); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, s) // From is filled in below from the usernames
		senders = append(senders, sender.Int64)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	names, err := p.h.Auth.Usernames(ctx, senders)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].From = displayName(names, senders[i])
		if folder == Sent {
			if out[i].To, err = p.recipients(ctx, out[i].ID); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func displayName(names map[int64]string, id int64) string {
	if n, ok := names[id]; ok {
		return n
	}
	return "former member"
}

func (p *Plugin) recipients(ctx context.Context, id int64) ([]string, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT user_id FROM messages_recipients WHERE message_id = ?`, id)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var uid int64
		if err := rows.Scan(&uid); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, uid)
	}
	rows.Close()
	names, err := p.h.Auth.Usernames(ctx, ids)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, uid := range ids {
		out = append(out, displayName(names, uid))
	}
	slices.Sort(out)
	return out, nil
}

// Message is a full message.
type Message struct {
	Summary
	Body     string
	ParentID int64
	SenderID int64
	Role     Role
	Deleted  bool // deleted by this member (recipient copy)
}

// Read returns a message the member sent or received, marking a received
// message as read.
func (p *Plugin) Read(ctx context.Context, user, id int64) (Message, error) {
	role, err := p.access(ctx, p.h.DB, user, id)
	if err != nil {
		return Message{}, err
	}
	var m Message
	var sender, parent sql.NullInt64
	var created string
	if err := p.h.DB.QueryRowContext(ctx, `SELECT id, sender_id, subject, body, parent_id, created_at FROM messages_messages WHERE id = ?`, id).
		Scan(&m.ID, &sender, &m.Subject, &m.Body, &parent, &created); err != nil {
		return Message{}, err
	}
	if m.CreatedAt, err = store.ParseTime(created); err != nil {
		return Message{}, err
	}
	m.SenderID, m.ParentID, m.Role = sender.Int64, parent.Int64, role
	names, err := p.h.Auth.Usernames(ctx, []int64{sender.Int64})
	if err != nil {
		return Message{}, err
	}
	m.From = displayName(names, sender.Int64)
	if m.To, err = p.recipients(ctx, id); err != nil {
		return Message{}, err
	}
	if role == RoleRecipient {
		var deleted sql.NullString
		if err := p.h.DB.QueryRowContext(ctx, `SELECT deleted_at FROM messages_recipients WHERE message_id = ? AND user_id = ?`, id, user).Scan(&deleted); err != nil {
			return Message{}, err
		}
		m.Deleted = deleted.Valid
		if _, err := p.h.DB.ExecContext(ctx, `UPDATE messages_recipients SET read_at = ? WHERE message_id = ? AND user_id = ? AND read_at IS NULL`,
			store.FormatTime(p.now()), id, user); err != nil {
			return Message{}, err
		}
	}
	m.Read = true
	return m, nil
}

// Delete removes a message from one of the member's folders: from Inbox it
// moves the received copy to Deleted; from Sent it removes the sent copy.
// The folder matters for a message sent to oneself, which is in both. It
// does not affect other members' copies.
func (p *Plugin) Delete(ctx context.Context, user, id int64, folder string) error {
	var res sql.Result
	var err error
	switch folder {
	case Inbox:
		res, err = p.h.DB.ExecContext(ctx, `UPDATE messages_recipients SET deleted_at = ? WHERE message_id = ? AND user_id = ? AND deleted_at IS NULL`,
			store.FormatTime(p.now()), id, user)
	case Sent:
		// Sent copies cannot be restored, so removing one may leave a
		// message nobody holds: remove its text too.
		return store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
			res, err := tx.ExecContext(ctx, `UPDATE messages_messages SET sender_deleted_at = ? WHERE id = ? AND sender_id = ? AND sender_deleted_at IS NULL`,
				store.FormatTime(p.now()), id, user)
			if err := affected(res, err); err != nil {
				return err
			}
			_, err = removeUnheld(ctx, tx)
			return err
		})
	default:
		return fmt.Errorf("%w: messages can be deleted from the inbox or Sent", ErrInvalid)
	}
	return affected(res, err)
}

// DeleteForever removes a message from the member's Deleted folder for
// good. Its text is removed once nobody else holds a copy.
func (p *Plugin) DeleteForever(ctx context.Context, user, id int64) error {
	return store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM messages_recipients WHERE message_id = ? AND user_id = ? AND deleted_at IS NOT NULL`, id, user)
		if err := affected(res, err); err != nil {
			return err
		}
		_, err = removeUnheld(ctx, tx)
		return err
	})
}

// EmptyDeleted removes every message in the member's Deleted folder for
// good and returns how many there were.
func (p *Plugin) EmptyDeleted(ctx context.Context, user int64) (int64, error) {
	var n int64
	err := store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM messages_recipients WHERE user_id = ? AND deleted_at IS NOT NULL`, user)
		if err != nil {
			return fmt.Errorf("messages: empty deleted: %w", err)
		}
		n, _ = res.RowsAffected()
		_, err = removeUnheld(ctx, tx)
		return err
	})
	if err == nil {
		p.h.Log.Info("deleted folder emptied", "user_id", user, "messages", n)
	}
	return n, err
}

// PurgeDeleted removes copies that have been in Deleted folders longer than
// DeletedDays, then the text of messages nobody holds any more. It returns
// the number of copies and of messages removed.
func (p *Plugin) PurgeDeleted(ctx context.Context) (copies, texts int64, err error) {
	cutoff := p.now().Add(-time.Duration(p.DeletedDays(ctx)) * 24 * time.Hour)
	err = store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM messages_recipients WHERE deleted_at IS NOT NULL AND deleted_at < ?`, store.FormatTime(cutoff))
		if err != nil {
			return fmt.Errorf("messages: purge deleted: %w", err)
		}
		copies, _ = res.RowsAffected()
		texts, err = removeUnheld(ctx, tx)
		return err
	})
	return copies, texts, err
}

// removeUnheld deletes messages that no member holds any more: no
// recipient copy is left (in an inbox or Deleted folder) and the sender has
// removed it from Sent or no longer has an account.
func removeUnheld(ctx context.Context, db store.DBTX) (int64, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM messages_messages
		WHERE (sender_deleted_at IS NOT NULL OR sender_id IS NULL)
		AND NOT EXISTS (SELECT 1 FROM messages_recipients r WHERE r.message_id = messages_messages.id)`)
	if err != nil {
		return 0, fmt.Errorf("messages: remove unheld: %w", err)
	}
	return res.RowsAffected()
}

// Restore moves a received message back from Deleted to the inbox. Sent
// messages cannot be restored.
func (p *Plugin) Restore(ctx context.Context, user, id int64) error {
	res, err := p.h.DB.ExecContext(ctx, `UPDATE messages_recipients SET deleted_at = NULL WHERE message_id = ? AND user_id = ? AND deleted_at IS NOT NULL`, id, user)
	return affected(res, err)
}

// affected maps an update that matched nothing (not the member's message,
// or not in that folder) to ErrNotFound.
func affected(res sql.Result, err error) error {
	if err != nil {
		return fmt.Errorf("messages: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Counts are a member's message statistics.
type Counts struct {
	Unread, Read, Deleted int
}

// Count returns a member's unread, read and deleted message counts.
func (p *Plugin) Count(ctx context.Context, user int64) (Counts, error) {
	var c Counts
	err := p.h.DB.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(deleted_at IS NULL AND read_at IS NULL), 0),
			COALESCE(SUM(deleted_at IS NULL AND read_at IS NOT NULL), 0),
			COALESCE(SUM(deleted_at IS NOT NULL), 0)
		FROM messages_recipients WHERE user_id = ?`, user).Scan(&c.Unread, &c.Read, &c.Deleted)
	return c, err
}
