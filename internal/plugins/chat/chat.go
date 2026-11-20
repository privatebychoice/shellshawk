// Package chat is the core Chat Channels plugin (docs/DESIGN.md §12):
// persistent channels run by moderators, invite-only ad hoc chats any member
// can start, and thread channels created by Conferences. Messages are
// delivered live and, unless a channel's retention is 0, logged for its
// retention period and downloadable over SFTP by members who can access it.
package chat

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"go.privatebychoice.com/shellshawk/internal/events"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Permissions.
const (
	PermUse      = "chat.use"      // join channels and talk
	PermCreate   = "chat.create"   // start ad hoc chats
	PermModerate = "chat.moderate" // manage persistent channels; kick, topic, destroy anywhere
)

// Channel kinds.
const (
	KindPersistent = "persistent"
	KindAdHoc      = "adhoc"
	KindThread     = "thread"
)

// Limits.
const (
	MaxMessage       = 500
	MaxTopic         = 120
	DefaultRetention = 90 // days; 0 = not logged
	MaxRetention     = 3650
	historyLines     = 50
)

// Errors.
var (
	ErrNotFound = errors.New("channel not found")
	ErrInvalid  = errors.New("invalid")
	ErrExists   = errors.New("a channel with that name already exists")
	ErrSlowDown = fmt.Errorf("slow down: at most %d messages every %d seconds", floodLines, int(floodWindow.Seconds()))
)

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// Plugin implements plugin.Plugin.
type Plugin struct {
	h   *plugin.Host
	hub *hub
	now func() time.Time
	// threadAccess decides who may enter thread channels, by the context
	// prefix of the plugin that owns them (see SetThreadAccess).
	threadAccess map[string]ThreadAccessFunc
	pages        pager
}

// ThreadAccessFunc reports whether user may enter the thread channel with
// the given context.
type ThreadAccessFunc func(ctx context.Context, user int64, context string) (bool, error)

// SetThreadAccess makes fn decide access to thread channels whose context
// starts with prefix, instead of the channel's groups, so the chat
// follows the owning feature's rules (e.g. a conference's groups). Call it
// before the server starts.
func (p *Plugin) SetThreadAccess(prefix string, fn ThreadAccessFunc) {
	if p.threadAccess == nil {
		p.threadAccess = map[string]ThreadAccessFunc{}
	}
	p.threadAccess[prefix] = fn
}

// New returns the Chat plugin.
func New() *Plugin { return &Plugin{hub: newHub(), now: time.Now} }

var _ plugin.Plugin = (*Plugin)(nil)

// Manifest implements plugin.Plugin.
func (p *Plugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID: "chat", Name: "Chat", Version: "1.0.0",
		Description: "Live chat channels",
		Permissions: []plugin.Permission{
			{Name: PermUse, Description: "Join chat channels and talk", DefaultGroups: []string{perm.GroupMember, perm.GroupModerator}},
			{Name: PermCreate, Description: "Start private ad hoc chats", DefaultGroups: []string{perm.GroupMember, perm.GroupModerator}},
			{Name: PermModerate, Description: "Manage channels; kick members, set topics and close chats anywhere", DefaultGroups: []string{perm.GroupModerator}},
			{Name: PermPage, Description: "Page members: ask them to come and talk in a chat", DefaultGroups: []string{perm.GroupMember, perm.GroupModerator}},
		},
		Settings: []plugin.Setting{pageSetting()},
		Migrations: []store.Migration{{Version: 1, Name: "chat", SQL: `
			-- permission: extra permission needed to join (persistent and
			-- thread channels). retention_days 0 means messages are not
			-- logged at all. context ties thread channels to their owner,
			-- e.g. 'conferences:thread:12'.
			CREATE TABLE chat_channels (
				id             INTEGER PRIMARY KEY,
				name           TEXT    NOT NULL COLLATE NOCASE UNIQUE,
				kind           TEXT    NOT NULL CHECK (kind IN ('persistent', 'adhoc', 'thread')),
				topic          TEXT    NOT NULL DEFAULT '',
				permission     TEXT    NOT NULL DEFAULT '',
				creator_id     INTEGER REFERENCES users (id) ON DELETE SET NULL,
				retention_days INTEGER NOT NULL DEFAULT 90 CHECK (retention_days BETWEEN 0 AND 3650),
				context        TEXT    NOT NULL DEFAULT '',
				created_at     TEXT    NOT NULL
			) STRICT;
			CREATE INDEX chat_channels_context ON chat_channels (context);

			-- Who may enter an ad hoc chat besides its creator.
			CREATE TABLE chat_invites (
				channel_id INTEGER NOT NULL REFERENCES chat_channels (id) ON DELETE CASCADE,
				user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
				PRIMARY KEY (channel_id, user_id)
			) STRICT;

			CREATE TABLE chat_messages (
				id         INTEGER PRIMARY KEY,
				channel_id INTEGER NOT NULL REFERENCES chat_channels (id) ON DELETE CASCADE,
				user_id    INTEGER REFERENCES users (id) ON DELETE SET NULL,
				kind       TEXT    NOT NULL CHECK (kind IN ('message', 'event')),
				body       TEXT    NOT NULL,
				created_at TEXT    NOT NULL
			) STRICT;
			CREATE INDEX chat_messages_channel ON chat_messages (channel_id, created_at);

			INSERT INTO chat_channels (name, kind, topic, created_at)
				VALUES ('lobby', 'persistent', 'General chat', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));`}, {Version: 2, Name: "channel groups", SQL: `
			-- Group channels: a restricted channel is open to members of any
			-- listed group (and administrators). A restricted channel whose
			-- groups were all deleted stays closed rather than opening to
			-- everyone. Thread channels follow their owner (SetThreadAccess).
			CREATE TABLE chat_channel_groups (
				channel_id INTEGER NOT NULL REFERENCES chat_channels (id) ON DELETE CASCADE,
				group_id   INTEGER NOT NULL REFERENCES access_groups (id) ON DELETE CASCADE,
				PRIMARY KEY (channel_id, group_id)
			) STRICT, WITHOUT ROWID;
			CREATE INDEX chat_channel_groups_group ON chat_channel_groups (group_id);

			ALTER TABLE chat_channels ADD COLUMN restricted INTEGER NOT NULL DEFAULT 0 CHECK (restricted IN (0, 1));

			-- Version 1 restricted a channel by one permission: convert it to
			-- the groups that held that permission.
			UPDATE chat_channels SET restricted = 1 WHERE permission <> '' AND kind <> 'adhoc';
			INSERT INTO chat_channel_groups (channel_id, group_id)
				SELECT c.id, gp.group_id FROM chat_channels c
				JOIN access_group_permissions gp ON gp.permission = c.permission
				WHERE c.permission <> '' AND c.kind <> 'adhoc';
			ALTER TABLE chat_channels DROP COLUMN permission;`}},
		MenuItems:     []plugin.MenuItem{{Key: "main", Label: "Chat", Help: "Live chat channels", AnyOf: []string{PermUse}, Run: p.run, WebPath: "/"}},
		Web:           p.webRoutes(),
		SFTP:          []sftpd.Mount{{Name: "chat", AnyOf: []string{PermUse}, FS: &logFS{p: p}}},
		Export:        p.export,
		Notifications: p.notificationKinds(),
	}
}

// Init implements plugin.Plugin. It starts the daily log purge, which runs
// until ctx ends.
func (p *Plugin) Init(ctx context.Context, h *plugin.Host) error {
	p.h = h
	if h.Events != nil {
		h.Events.Subscribe(events.UserErased, "chat", p.erase)
	}
	go func() {
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			if n, err := p.PurgeExpired(ctx); err != nil && ctx.Err() == nil {
				h.Log.Error("chat log purge failed", "err", err)
			} else if n > 0 {
				h.Log.Info("chat log purged", "messages", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	return nil
}

// Channel is a chat channel.
type Channel struct {
	ID    int64
	Name  string
	Kind  string
	Topic string
	// Restricted persistent channels are open only to members of Groups
	// (group IDs) and administrators.
	Restricted    bool
	Groups        []int64
	CreatorID     int64
	RetentionDays int
	Context       string
}

// Tag is the one-letter channel type shown in listings: [P] persistent,
// [A] ad hoc (private), [T] thread.
func (c Channel) Tag() string {
	switch c.Kind {
	case KindAdHoc:
		return "[A]"
	case KindThread:
		return "[T]"
	}
	return "[P]"
}

// KindName is the channel type in words.
func (c Channel) KindName() string {
	switch c.Kind {
	case KindAdHoc:
		return "private chat"
	case KindThread:
		return "thread chat"
	}
	return "channel"
}

const channelCols = `id, name, kind, topic, restricted,
	COALESCE((SELECT group_concat(group_id) FROM chat_channel_groups WHERE channel_id = chat_channels.id), ''),
	COALESCE(creator_id, 0), retention_days, context`

func scanChannel(row interface{ Scan(...any) error }) (Channel, error) {
	var c Channel
	var groups string
	err := row.Scan(&c.ID, &c.Name, &c.Kind, &c.Topic, &c.Restricted, &groups, &c.CreatorID, &c.RetentionDays, &c.Context)
	for _, g := range strings.Split(groups, ",") {
		if id, perr := strconv.ParseInt(g, 10, 64); perr == nil {
			c.Groups = append(c.Groups, id)
		}
	}
	return c, err
}

// Get returns a channel by ID.
func (p *Plugin) Get(ctx context.Context, id int64) (Channel, error) {
	c, err := scanChannel(p.h.DB.QueryRowContext(ctx, `SELECT `+channelCols+` FROM chat_channels WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Channel{}, ErrNotFound
	}
	return c, err
}

// ByName returns a channel by name (case-insensitive).
func (p *Plugin) ByName(ctx context.Context, name string) (Channel, error) {
	c, err := scanChannel(p.h.DB.QueryRowContext(ctx, `SELECT `+channelCols+` FROM chat_channels WHERE name = ?`, strings.TrimPrefix(strings.TrimSpace(name), "#")))
	if errors.Is(err, sql.ErrNoRows) {
		return Channel{}, ErrNotFound
	}
	return c, err
}

// CanAccess reports whether user may enter c.
func (p *Plugin) CanAccess(ctx context.Context, user int64, c Channel) (bool, error) {
	v, err := p.newViewer(ctx, user)
	if err != nil {
		return false, err
	}
	return v.canAccess(ctx, c)
}

// viewer is what access checks need to know about one member. Groups and
// private-chat invitations are loaded on first use and then reused, so
// checking a whole channel list costs a few queries, not a few per
// channel.
type viewer struct {
	p       *Plugin
	user    int64
	set     perm.Set
	groups  map[int64]bool
	invited map[int64]bool
}

func (p *Plugin) newViewer(ctx context.Context, user int64) (*viewer, error) {
	set, err := p.h.Perms.Permissions(ctx, user)
	if err != nil {
		return nil, err
	}
	return &viewer{p: p, user: user, set: set}, nil
}

func (v *viewer) canAccess(ctx context.Context, c Channel) (bool, error) {
	if !v.set.Has(PermUse) {
		return false, nil
	}
	switch c.Kind {
	case KindAdHoc:
		if c.CreatorID == v.user || v.set.Has(PermModerate) {
			return true, nil
		}
		if v.invited == nil {
			inv, err := v.p.invitedChannels(ctx, v.user)
			if err != nil {
				return false, err
			}
			v.invited = inv
		}
		return v.invited[c.ID], nil
	case KindThread:
		for prefix, fn := range v.p.threadAccess {
			if strings.HasPrefix(c.Context, prefix) {
				return fn(ctx, v.user, c.Context)
			}
		}
	}
	if !c.Restricted || v.set.Has(perm.Admin) {
		return true, nil
	}
	if v.groups == nil {
		g, err := v.p.h.Perms.UserGroupIDs(ctx, v.user)
		if err != nil {
			return false, err
		}
		v.groups = g
	}
	for _, g := range c.Groups {
		if v.groups[g] {
			return true, nil
		}
	}
	return false, nil
}

// invitedChannels returns the private chats user has been invited to.
func (p *Plugin) invitedChannels(ctx context.Context, user int64) (map[int64]bool, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT channel_id FROM chat_invites WHERE user_id = ?`, user)
	if err != nil {
		return nil, fmt.Errorf("chat: invitations: %w", err)
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// canModerate reports whether user may kick, change the topic or close c.
func (p *Plugin) canModerate(ctx context.Context, user int64, c Channel) (bool, error) {
	set, err := p.h.Perms.Permissions(ctx, user)
	if err != nil {
		return false, err
	}
	return set.Has(PermModerate) || (c.Kind == KindAdHoc && c.CreatorID == user && user != 0), nil
}

// FindAccessible returns the channels user may enter whose name or topic
// contains query (case-insensitive; a leading # is ignored).
func (p *Plugin) FindAccessible(ctx context.Context, user int64, query string) ([]Channel, error) {
	q := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(query), "#"))
	if q == "" {
		return nil, fmt.Errorf("%w: type a channel name, or part of one", ErrInvalid)
	}
	all, err := p.Accessible(ctx, user)
	if err != nil {
		return nil, err
	}
	var out []Channel
	for _, c := range all {
		if strings.Contains(strings.ToLower(c.Name), q) || strings.Contains(strings.ToLower(c.Topic), q) {
			out = append(out, c)
		}
	}
	return out, nil
}

// Accessible lists the channels user may enter: persistent and thread
// channels first, then ad hoc chats, by name.
func (p *Plugin) Accessible(ctx context.Context, user int64) ([]Channel, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT `+channelCols+` FROM chat_channels ORDER BY kind = 'adhoc', name`)
	if err != nil {
		return nil, fmt.Errorf("chat: list: %w", err)
	}
	var all []Channel
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, c)
	}
	rows.Close()
	v, err := p.newViewer(ctx, user)
	if err != nil {
		return nil, err
	}
	var out []Channel
	for _, c := range all {
		ok, err := v.canAccess(ctx, c)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, c)
		}
	}
	return out, nil
}

func cleanName(name string) (string, error) {
	name = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "#"))
	if !namePattern.MatchString(name) {
		return "", fmt.Errorf("%w: channel names are 2-32 lowercase letters, digits or '-', starting with a letter", ErrInvalid)
	}
	return name, nil
}

func cleanTopic(t string) (string, error) {
	t = strings.TrimSpace(t)
	if utf8.RuneCountInString(t) > MaxTopic || term.Sanitize(t, false) != t {
		return "", fmt.Errorf("%w: topics are at most %d printable characters", ErrInvalid, MaxTopic)
	}
	return t, nil
}

// NewChannel describes a channel to create.
type NewChannel struct {
	Name  string
	Kind  string
	Topic string
	// Groups, for persistent channels: only members of one of them (and
	// administrators) may join. None means anyone who can chat.
	Groups        []int64
	RetentionDays int
	Context       string
}

// Create makes a channel. Persistent channels need chat.moderate, ad hoc
// chats chat.create; thread channels are created by other plugins through
// EnsureThreadChannel.
func (p *Plugin) Create(ctx context.Context, actor int64, n NewChannel) (int64, error) {
	set, err := p.h.Perms.Permissions(ctx, actor)
	if err != nil {
		return 0, err
	}
	switch n.Kind {
	case KindPersistent:
		if !set.Has(PermModerate) {
			return 0, perm.ErrForbidden
		}
	case KindAdHoc:
		if !set.Has(PermCreate) {
			return 0, perm.ErrForbidden
		}
		n.Groups = nil
	default:
		return 0, fmt.Errorf("%w: kind", ErrInvalid)
	}
	return p.insert(ctx, actor, n)
}

func (p *Plugin) insert(ctx context.Context, creator int64, n NewChannel) (int64, error) {
	name, err := cleanName(n.Name)
	if err != nil {
		return 0, err
	}
	topic, err := cleanTopic(n.Topic)
	if err != nil {
		return 0, err
	}
	for _, g := range n.Groups {
		if _, err := p.h.Perms.GroupByID(ctx, g); err != nil {
			return 0, fmt.Errorf("%w: unknown group %d", ErrInvalid, g)
		}
	}
	if n.RetentionDays < 0 || n.RetentionDays > MaxRetention {
		return 0, fmt.Errorf("%w: retention must be 0 to %d days", ErrInvalid, MaxRetention)
	}
	var creatorArg any
	if creator != 0 {
		creatorArg = creator
	}
	var id int64
	err = store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO chat_channels (name, kind, topic, restricted, creator_id, retention_days, context, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (name) DO NOTHING`,
			name, n.Kind, topic, len(n.Groups) > 0, creatorArg, n.RetentionDays, n.Context, store.FormatTime(p.now()))
		if err != nil {
			return fmt.Errorf("chat: create: %w", err)
		}
		if rows, _ := res.RowsAffected(); rows == 0 {
			return ErrExists
		}
		id, _ = res.LastInsertId()
		for _, g := range n.Groups {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO chat_channel_groups (channel_id, group_id) VALUES (?, ?)`, id, g); err != nil {
				return fmt.Errorf("chat: create: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	p.h.Log.Info("channel created", "channel_id", id, "kind", n.Kind, "creator", creator, "groups", len(n.Groups))
	return id, nil
}

// EnsureThreadChannel returns the thread channel for context, creating it
// if needed. For use by other plugins, which decide who may join through
// SetThreadAccess.
func (p *Plugin) EnsureThreadChannel(ctx context.Context, context, name, topic string) (int64, error) {
	var id int64
	err := p.h.DB.QueryRowContext(ctx, `SELECT id FROM chat_channels WHERE kind = 'thread' AND context = ?`, context).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	return p.insert(ctx, 0, NewChannel{Name: name, Kind: KindThread, Topic: topic, RetentionDays: DefaultRetention, Context: context})
}

// Destroy deletes a channel and its log, removing anyone inside. Ad hoc
// chats: their creator or a chat moderator. Others: chat moderators.
func (p *Plugin) Destroy(ctx context.Context, actor int64, id int64) error {
	c, err := p.Get(ctx, id)
	if err != nil {
		return err
	}
	if ok, err := p.canModerate(ctx, actor, c); err != nil || !ok {
		return errors.Join(perm.ErrForbidden, err)
	}
	if _, err := p.h.DB.ExecContext(ctx, `DELETE FROM chat_channels WHERE id = ?`, id); err != nil {
		return fmt.Errorf("chat: destroy: %w", err)
	}
	p.hub.closeRoom(id, "This chat was closed.")
	p.h.Log.Info("channel destroyed", "channel_id", id, "actor", actor)
	return nil
}

// SetTopic changes a channel's topic.
func (p *Plugin) SetTopic(ctx context.Context, actor int64, c Channel, topic string) error {
	if ok, err := p.canModerate(ctx, actor, c); err != nil || !ok {
		return errors.Join(perm.ErrForbidden, err)
	}
	topic, err := cleanTopic(topic)
	if err != nil {
		return err
	}
	_, err = p.h.DB.ExecContext(ctx, `UPDATE chat_channels SET topic = ? WHERE id = ?`, topic, c.ID)
	return err
}

// SetRetention changes how long a channel's messages are logged
// (chat.moderate). 0 stops logging and deletes the existing log.
func (p *Plugin) SetRetention(ctx context.Context, actor int64, c Channel, days int) error {
	if err := p.h.Perms.Require(ctx, actor, PermModerate); err != nil {
		return err
	}
	if days < 0 || days > MaxRetention {
		return fmt.Errorf("%w: retention must be 0 to %d days", ErrInvalid, MaxRetention)
	}
	return store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE chat_channels SET retention_days = ? WHERE id = ?`, days, c.ID); err != nil {
			return err
		}
		if days == 0 {
			_, err := tx.ExecContext(ctx, `DELETE FROM chat_messages WHERE channel_id = ?`, c.ID)
			return err
		}
		return nil
	})
}

// Invite allows user to enter an ad hoc chat.
func (p *Plugin) Invite(ctx context.Context, actor int64, c Channel, user int64) error {
	if c.Kind != KindAdHoc {
		return fmt.Errorf("%w: only private chats use invitations", ErrInvalid)
	}
	if ok, err := p.CanAccess(ctx, actor, c); err != nil || !ok {
		return errors.Join(perm.ErrForbidden, err)
	}
	_, err := p.h.DB.ExecContext(ctx, `INSERT INTO chat_invites (channel_id, user_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, c.ID, user)
	return err
}

// Invitee is a member invited to a private chat.
type Invitee struct {
	ID   int64
	Name string
}

// Invited returns the members invited to private chat c, by name. Callers
// check that the viewer may enter c.
func (p *Plugin) Invited(ctx context.Context, c Channel) ([]Invitee, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT user_id FROM chat_invites WHERE channel_id = ?`, c.ID)
	if err != nil {
		return nil, fmt.Errorf("chat: invited: %w", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	names, err := p.h.Auth.Usernames(ctx, ids)
	if err != nil {
		return nil, err
	}
	var out []Invitee
	for _, id := range ids {
		if n, ok := names[id]; ok {
			out = append(out, Invitee{id, n})
		}
	}
	slices.SortFunc(out, func(a, b Invitee) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// Kick removes user from c now. In an ad hoc chat their invitation is
// withdrawn too; elsewhere they may rejoin later.
func (p *Plugin) Kick(ctx context.Context, actor int64, c Channel, user int64) error {
	if ok, err := p.canModerate(ctx, actor, c); err != nil || !ok {
		return errors.Join(perm.ErrForbidden, err)
	}
	if c.Kind == KindAdHoc {
		if _, err := p.h.DB.ExecContext(ctx, `DELETE FROM chat_invites WHERE channel_id = ? AND user_id = ?`, c.ID, user); err != nil {
			return err
		}
	}
	p.hub.kick(c.ID, user, "You were removed from this chat.")
	p.h.Log.Info("member kicked", "channel_id", c.ID, "user_id", user, "actor", actor)
	return nil
}

// Entry is a logged chat line.
type Entry struct {
	At     time.Time
	UserID int64
	Name   string
	Kind   string // "message" or "event"
	Body   string
}

// record logs a line if the channel is logged.
// cleanMessage checks a message: one line of printable text, at most
// MaxMessage characters.
func cleanMessage(text string) (string, error) {
	text = strings.TrimSpace(text)
	switch {
	case text == "":
		return "", fmt.Errorf("%w: the message is empty", ErrInvalid)
	case utf8.RuneCountInString(text) > MaxMessage:
		return "", fmt.Errorf("%w: messages are at most %d characters", ErrInvalid, MaxMessage)
	case term.Sanitize(text, false) != text:
		return "", fmt.Errorf("%w: messages must be one line of printable text", ErrInvalid)
	}
	return text, nil
}

// Say sends a message from u to c: checked, flood-limited, logged if c is
// logged, and delivered to everyone in c. Callers check access first.
func (p *Plugin) Say(ctx context.Context, c Channel, u auth.User, text string) error {
	text, err := cleanMessage(text)
	if err != nil {
		return err
	}
	now := p.now()
	if !p.hub.allow(u.ID, now) {
		return ErrSlowDown
	}
	if err := p.record(ctx, c, u.ID, "message", text, now); err != nil {
		return fmt.Errorf("chat: log message: %w", err)
	}
	p.hub.broadcast(c.ID, messageLine(now, u.Username, text))
	return nil
}

func (p *Plugin) record(ctx context.Context, c Channel, user int64, kind, body string, at time.Time) error {
	if c.RetentionDays == 0 {
		return nil
	}
	var u any
	if user != 0 {
		u = user
	}
	_, err := p.h.DB.ExecContext(ctx, `INSERT INTO chat_messages (channel_id, user_id, kind, body, created_at) VALUES (?, ?, ?, ?, ?)`,
		c.ID, u, kind, body, store.FormatTime(at))
	return err
}

// History returns up to limit logged lines of c, oldest first, optionally
// limited to [from, to).
func (p *Plugin) History(ctx context.Context, c Channel, limit int, from, to time.Time) ([]Entry, error) {
	q := `SELECT created_at, COALESCE(user_id, 0), kind, body FROM chat_messages WHERE channel_id = ?`
	args := []any{c.ID}
	if !from.IsZero() {
		q += ` AND created_at >= ? AND created_at < ?`
		args = append(args, store.FormatTime(from), store.FormatTime(to))
	}
	q += ` ORDER BY created_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := p.h.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("chat: history: %w", err)
	}
	var out []Entry
	var ids []int64
	for rows.Next() {
		var e Entry
		var at string
		if err := rows.Scan(&at, &e.UserID, &e.Kind, &e.Body); err != nil {
			rows.Close()
			return nil, err
		}
		if e.At, err = store.ParseTime(at); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, e)
		ids = append(ids, e.UserID)
	}
	rows.Close()
	names, err := p.h.Auth.Usernames(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if n, ok := names[out[i].UserID]; ok {
			out[i].Name = n
		} else {
			out[i].Name = "former member"
		}
	}
	// Oldest first.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// PurgeExpired deletes logged lines older than each channel's retention.
func (p *Plugin) PurgeExpired(ctx context.Context) (int64, error) {
	res, err := p.h.DB.ExecContext(ctx, `
		DELETE FROM chat_messages WHERE id IN (
			SELECT m.id FROM chat_messages m JOIN chat_channels c ON c.id = m.channel_id
			WHERE m.created_at < strftime('%Y-%m-%dT%H:%M:%SZ', ?, '-' || c.retention_days || ' days'))`,
		store.FormatTime(p.now()))
	if err != nil {
		return 0, fmt.Errorf("chat: purge: %w", err)
	}
	return res.RowsAffected()
}

// DestroyContext deletes the thread channel for context (and its log), if
// any, for plugins removing the content it belonged to. It performs no
// permission check: the calling plugin has already checked its own.
func (p *Plugin) DestroyContext(ctx context.Context, channelContext string) error {
	var id int64
	err := p.h.DB.QueryRowContext(ctx, `SELECT id FROM chat_channels WHERE kind = 'thread' AND context = ?`, channelContext).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := p.h.DB.ExecContext(ctx, `DELETE FROM chat_channels WHERE id = ?`, id); err != nil {
		return err
	}
	p.hub.closeRoom(id, "This thread chat was closed.")
	return nil
}
