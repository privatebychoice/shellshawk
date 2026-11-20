// Package conferences is the core Conferences plugin (docs/DESIGN.md §12): a
// forum of areas and conferences, threads of markdown posts, optional polls
// on posts, an optional live chat per thread, and whole threads downloadable
// over SFTP.
package conferences

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"go.privatebychoice.com/shellshawk/internal/events"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/chat"
	"go.privatebychoice.com/shellshawk/internal/plugins/polls"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Permissions.
const (
	PermRead     = "conferences.read"
	PermPost     = "conferences.post"
	PermModerate = "conferences.moderate" // manage areas/conferences, edit or delete any post, lock threads, enable chat
)

// Limits.
const (
	MaxTitle       = 120
	MaxName        = 60
	MaxDescription = 200
	threadLimit    = 100
	setMaxBody     = "max_body"
	// setMaxPostsPerHour caps replies and new threads per member per hour
	// (moderators are exempt), so a script cannot flood threads and the
	// reply notifications they send.
	setMaxPostsPerHour     = "max_posts_per_hour"
	defaultMaxPostsPerHour = 30
)

// Errors.
var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid")
	ErrLocked   = errors.New("this thread is locked")
	ErrNotEmpty = errors.New("remove its conferences first")
	ErrExists   = errors.New("that short name is already used")
)

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)

// Plugin implements plugin.Plugin.
type Plugin struct {
	h     *plugin.Host
	polls *polls.Plugin // optional
	chat  *chat.Plugin  // optional
	now   func() time.Time
}

// New returns the Conferences plugin. pollsPlugin and chatPlugin may be nil
// to build without polls on posts or thread chats.
func New(pollsPlugin *polls.Plugin, chatPlugin *chat.Plugin) *Plugin {
	p := &Plugin{polls: pollsPlugin, chat: chatPlugin, now: time.Now}
	if chatPlugin != nil {
		chatPlugin.SetThreadAccess(threadChatPrefix, p.chatAccess)
	}
	return p
}

var _ plugin.Plugin = (*Plugin)(nil)

// Manifest implements plugin.Plugin.
func (p *Plugin) Manifest() plugin.Manifest {
	everyone := []string{perm.GroupMember, perm.GroupModerator}
	return plugin.Manifest{
		ID: "conferences", Name: "Conferences", Version: "1.0.0",
		Description: "Discussion areas, conferences and threads",
		Permissions: []plugin.Permission{
			{Name: PermRead, Description: "Read conferences", DefaultGroups: everyone},
			{Name: PermPost, Description: "Start threads and reply", DefaultGroups: everyone},
			{Name: PermModerate, Description: "Manage conferences and moderate posts", DefaultGroups: []string{perm.GroupModerator}},
		},
		Settings: []plugin.Setting{{
			Field: form.Field{Name: setMaxBody, Label: "Maximum post length (characters)", Kind: form.SingleLine, Subtype: form.Int,
				Required: true, Min: form.Bound(100), Max: form.Bound(100000)},
			Default: "20000",
		}, {
			Field: form.Field{Name: setMaxPostsPerHour, Label: "Maximum posts (replies and new threads) a member can make per hour",
				Help: "Moderators are not limited.", Kind: form.SingleLine, Subtype: form.Int, Required: true, Min: form.Bound(1), Max: form.Bound(1000)},
			Default: strconv.Itoa(defaultMaxPostsPerHour),
		}},
		Migrations: []store.Migration{{Version: 1, Name: "conferences", SQL: `
			CREATE TABLE conferences_areas (
				id          INTEGER PRIMARY KEY,
				slug        TEXT    NOT NULL COLLATE NOCASE UNIQUE,
				name        TEXT    NOT NULL,
				description TEXT    NOT NULL DEFAULT '',
				position    INTEGER NOT NULL,
				created_at  TEXT    NOT NULL
			) STRICT;

			-- permission: extra permission needed to read and post here
			-- (the per-conference group check), or ''.
			CREATE TABLE conferences_conferences (
				id          INTEGER PRIMARY KEY,
				area_id     INTEGER NOT NULL REFERENCES conferences_areas (id) ON DELETE CASCADE,
				slug        TEXT    NOT NULL COLLATE NOCASE,
				name        TEXT    NOT NULL,
				description TEXT    NOT NULL DEFAULT '',
				permission  TEXT    NOT NULL DEFAULT '',
				position    INTEGER NOT NULL,
				created_at  TEXT    NOT NULL,
				UNIQUE (area_id, slug)
			) STRICT;

			CREATE TABLE conferences_threads (
				id              INTEGER PRIMARY KEY,
				conference_id   INTEGER NOT NULL REFERENCES conferences_conferences (id) ON DELETE CASCADE,
				title           TEXT    NOT NULL,
				author_id       INTEGER REFERENCES users (id) ON DELETE SET NULL,
				created_at      TEXT    NOT NULL,
				last_post_at    TEXT    NOT NULL,
				locked          INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1)),
				chat_channel_id INTEGER
			) STRICT;
			CREATE INDEX conferences_threads_conf ON conferences_threads (conference_id, last_post_at);

			CREATE TABLE conferences_posts (
				id         INTEGER PRIMARY KEY,
				thread_id  INTEGER NOT NULL REFERENCES conferences_threads (id) ON DELETE CASCADE,
				author_id  INTEGER REFERENCES users (id) ON DELETE SET NULL,
				body       TEXT    NOT NULL,
				created_at TEXT    NOT NULL,
				edited_at  TEXT
			) STRICT;
			CREATE INDEX conferences_posts_thread ON conferences_posts (thread_id, created_at);

			INSERT INTO conferences_areas (slug, name, description, position, created_at)
				VALUES ('general', 'General', 'Everything else', 1, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
			INSERT INTO conferences_conferences (area_id, slug, name, description, position, created_at)
				SELECT id, 'general', 'General discussion', 'Introduce yourself and talk about anything', 1, created_at
				FROM conferences_areas WHERE slug = 'general';`}, {Version: 2, Name: "conference groups", SQL: `
			-- Group-only conferences: restricted conferences are open to
			-- members of any listed group (and administrators). A restricted
			-- conference whose groups were all deleted stays closed rather
			-- than opening to everyone.
			CREATE TABLE conferences_conference_groups (
				conference_id INTEGER NOT NULL REFERENCES conferences_conferences (id) ON DELETE CASCADE,
				group_id      INTEGER NOT NULL REFERENCES access_groups (id) ON DELETE CASCADE,
				PRIMARY KEY (conference_id, group_id)
			) STRICT, WITHOUT ROWID;
			CREATE INDEX conferences_conference_groups_group ON conferences_conference_groups (group_id);

			ALTER TABLE conferences_conferences ADD COLUMN restricted INTEGER NOT NULL DEFAULT 0 CHECK (restricted IN (0, 1));

			-- Version 1 restricted a conference by one permission: convert it
			-- to the groups that held that permission.
			UPDATE conferences_conferences SET restricted = 1 WHERE permission <> '';
			INSERT INTO conferences_conference_groups (conference_id, group_id)
				SELECT c.id, gp.group_id FROM conferences_conferences c
				JOIN access_group_permissions gp ON gp.permission = c.permission
				WHERE c.permission <> '';
			ALTER TABLE conferences_conferences DROP COLUMN permission;`}},
		MenuItems:     []plugin.MenuItem{{Key: "main", Label: "Conferences", Help: "Discussion areas and threads", AnyOf: []string{PermRead}, Run: p.run, WebPath: "/"}},
		SFTP:          []sftpd.Mount{{Name: "conferences", AnyOf: []string{PermRead}, FS: &threadFS{p: p}}},
		Export:        p.export,
		Web:           p.webRoutes(),
		Notifications: p.notificationKinds(),
	}
}

// Init implements plugin.Plugin.
func (p *Plugin) Init(_ context.Context, h *plugin.Host) error {
	p.h = h
	if h.Events != nil {
		h.Events.Subscribe(events.UserErased, "conferences", p.erase)
	}
	return nil
}

// Area groups conferences.
type Area struct {
	ID          int64
	Slug, Name  string
	Description string
}

// Conference holds threads.
type Conference struct {
	ID, AreaID  int64
	AreaSlug    string
	Slug, Name  string
	Description string
	// Restricted conferences are open only to members of Groups (group
	// IDs) and administrators.
	Restricted bool
	Groups     []int64
}

// Thread is a discussion.
type Thread struct {
	ID, ConferenceID int64
	Title            string
	AuthorID         int64
	Author           string
	CreatedAt        time.Time
	LastPostAt       time.Time
	Locked           bool
	ChatChannelID    int64
	Posts            int
}

// Post is one message in a thread.
type Post struct {
	ID, ThreadID int64
	AuthorID     int64
	Author       string
	Body         string
	CreatedAt    time.Time
	EditedAt     *time.Time
	Polls        []int64
}

func clean(s string, max int, required bool) (string, bool) {
	s = strings.TrimSpace(s)
	n := utf8.RuneCountInString(s)
	return s, (!required || n > 0) && n <= max && term.Sanitize(s, false) == s
}

func (p *Plugin) maxBody(ctx context.Context) int {
	v, err := p.h.Settings.Get(ctx, setMaxBody)
	if err != nil {
		return 20000
	}
	n, _ := strconv.Atoi(v)
	return n
}

func (p *Plugin) checkBody(ctx context.Context, body string) (string, error) {
	body = strings.TrimRight(body, " \n\t")
	if n := utf8.RuneCountInString(body); n == 0 || n > p.maxBody(ctx) {
		return "", fmt.Errorf("%w: posts must be 1 to %d characters", ErrInvalid, p.maxBody(ctx))
	}
	if !utf8.ValidString(body) || term.Sanitize(body, true) != strings.ReplaceAll(body, "\t", " ") {
		return "", fmt.Errorf("%w: the post contains control characters", ErrInvalid)
	}
	return body, nil
}

// ---- areas and conferences ---------------------------------------------------

// Areas lists all areas in order.
func (p *Plugin) Areas(ctx context.Context) ([]Area, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT id, slug, name, description FROM conferences_areas ORDER BY position, name`)
	if err != nil {
		return nil, fmt.Errorf("conferences: areas: %w", err)
	}
	defer rows.Close()
	var out []Area
	for rows.Next() {
		var a Area
		if err := rows.Scan(&a.ID, &a.Slug, &a.Name, &a.Description); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

const confCols = `c.id, c.area_id, a.slug, c.slug, c.name, c.description, c.restricted,
	COALESCE((SELECT group_concat(group_id) FROM conferences_conference_groups WHERE conference_id = c.id), '')`

func scanConf(row interface{ Scan(...any) error }) (Conference, error) {
	var c Conference
	var groups string
	if err := row.Scan(&c.ID, &c.AreaID, &c.AreaSlug, &c.Slug, &c.Name, &c.Description, &c.Restricted, &groups); err != nil {
		return c, err
	}
	for _, g := range strings.Split(groups, ",") {
		if id, err := strconv.ParseInt(g, 10, 64); err == nil {
			c.Groups = append(c.Groups, id)
		}
	}
	return c, nil
}

// Conferences lists an area's conferences the member may read.
func (p *Plugin) Conferences(ctx context.Context, user, area int64) ([]Conference, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT `+confCols+` FROM conferences_conferences c JOIN conferences_areas a ON a.id = c.area_id
		WHERE c.area_id = ? ORDER BY c.position, c.name`, area)
	if err != nil {
		return nil, fmt.Errorf("conferences: list: %w", err)
	}
	var all []Conference
	for rows.Next() {
		c, err := scanConf(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		all = append(all, c)
	}
	rows.Close()
	set, groups, err := p.viewer(ctx, user)
	if err != nil {
		return nil, err
	}
	var out []Conference
	for _, c := range all {
		if canRead(set, groups, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// Conference returns one conference.
func (p *Plugin) Conference(ctx context.Context, id int64) (Conference, error) {
	c, err := scanConf(p.h.DB.QueryRowContext(ctx, `SELECT `+confCols+` FROM conferences_conferences c
		JOIN conferences_areas a ON a.id = c.area_id WHERE c.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Conference{}, ErrNotFound
	}
	return c, err
}

// viewer loads what canRead needs about user: permissions and group IDs.
func (p *Plugin) viewer(ctx context.Context, user int64) (perm.Set, map[int64]bool, error) {
	set, err := p.h.Perms.Permissions(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	groups, err := p.h.Perms.UserGroupIDs(ctx, user)
	return set, groups, err
}

// canRead: conferences.read, and for a restricted conference membership of
// one of its groups. Administrators can read every conference.
func canRead(set perm.Set, groups map[int64]bool, c Conference) bool {
	if !set.Has(PermRead) {
		return false
	}
	if !c.Restricted || set.Has(perm.Admin) {
		return true
	}
	for _, g := range c.Groups {
		if groups[g] {
			return true
		}
	}
	return false
}

// canPost requires c to come from access, which has checked read access.
func canPost(set perm.Set, _ Conference) bool { return set.Has(PermPost) }

// access loads the conference and the member's permissions, requiring read
// access. Conferences the member cannot read are reported as not found.
func (p *Plugin) access(ctx context.Context, user, conf int64) (Conference, perm.Set, error) {
	c, err := p.Conference(ctx, conf)
	if err != nil {
		return Conference{}, nil, err
	}
	set, groups, err := p.viewer(ctx, user)
	if err != nil {
		return Conference{}, nil, err
	}
	if !canRead(set, groups, c) {
		return Conference{}, nil, ErrNotFound
	}
	return c, set, nil
}

// CreateArea adds an area (moderators).
func (p *Plugin) CreateArea(ctx context.Context, actor int64, slug, name, desc string) (int64, error) {
	if err := p.h.Perms.Require(ctx, actor, PermModerate); err != nil {
		return 0, err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	name, okN := clean(name, MaxName, true)
	desc, okD := clean(desc, MaxDescription, false)
	if !slugPattern.MatchString(slug) || !okN || !okD {
		return 0, fmt.Errorf("%w: short name 2-32 lowercase letters, digits or '-'; name 1-%d and description up to %d printable characters", ErrInvalid, MaxName, MaxDescription)
	}
	// "WHERE true" is required: without a WHERE clause SQLite parses
	// "FROM t ON CONFLICT" as a join constraint (see SQLite upsert docs).
	res, err := p.h.DB.ExecContext(ctx, `INSERT INTO conferences_areas (slug, name, description, position, created_at)
		SELECT ?, ?, ?, COALESCE(MAX(position), 0) + 1, ? FROM conferences_areas WHERE true
		ON CONFLICT DO NOTHING`,
		slug, name, desc, store.FormatTime(p.now()))
	if err != nil {
		return 0, fmt.Errorf("conferences: create area: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrExists
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// CreateConference adds a conference to an area (moderators). With no
// groups every member who can read conferences may use it; otherwise only
// members of one of the groups (and administrators).
func (p *Plugin) CreateConference(ctx context.Context, actor, area int64, slug, name, desc string, groups []int64) (int64, error) {
	if err := p.h.Perms.Require(ctx, actor, PermModerate); err != nil {
		return 0, err
	}
	slug = strings.ToLower(strings.TrimSpace(slug))
	name, okN := clean(name, MaxName, true)
	desc, okD := clean(desc, MaxDescription, false)
	if !slugPattern.MatchString(slug) || !okN || !okD {
		return 0, fmt.Errorf("%w: short name 2-32 lowercase letters, digits or '-'; name 1-%d and description up to %d printable characters", ErrInvalid, MaxName, MaxDescription)
	}
	for _, g := range groups {
		grp, err := p.h.Perms.GroupByID(ctx, g)
		if err != nil {
			return 0, fmt.Errorf("%w: unknown group %d", ErrInvalid, g)
		}
		if perm.IsEveryoneGroup(grp) {
			return 0, fmt.Errorf("%w: the member group includes every account, so it cannot limit who can use a conference; choose another group", ErrInvalid)
		}
	}
	var id int64
	err := store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO conferences_conferences (area_id, slug, name, description, restricted, position, created_at)
			SELECT ?, ?, ?, ?, ?, COALESCE(MAX(position), 0) + 1, ? FROM conferences_conferences WHERE area_id = ?
			ON CONFLICT DO NOTHING`, area, slug, name, desc, len(groups) > 0, store.FormatTime(p.now()), area)
		if err != nil {
			return fmt.Errorf("conferences: create conference: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrExists
		}
		id, _ = res.LastInsertId()
		for _, g := range groups {
			if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO conferences_conference_groups (conference_id, group_id) VALUES (?, ?)`, id, g); err != nil {
				return fmt.Errorf("conferences: create conference: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	p.h.Log.Info("conference created", "conference_id", id, "area_id", area, "actor", actor, "groups", len(groups))
	return id, nil
}

// DeleteConference deletes a conference with all its threads, posts, polls
// and thread chats (moderators).
func (p *Plugin) DeleteConference(ctx context.Context, actor, conf int64) error {
	if err := p.h.Perms.Require(ctx, actor, PermModerate); err != nil {
		return err
	}
	threads, err := p.threadIDs(ctx, `conference_id = ?`, conf)
	if err != nil {
		return err
	}
	for _, t := range threads {
		if err := p.cleanupThread(ctx, t); err != nil {
			return err
		}
	}
	res, err := p.h.DB.ExecContext(ctx, `DELETE FROM conferences_conferences WHERE id = ?`, conf)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	p.h.Log.Info("conference deleted", "conference_id", conf, "actor", actor)
	return nil
}

// DeleteArea deletes an empty area (moderators).
func (p *Plugin) DeleteArea(ctx context.Context, actor, area int64) error {
	if err := p.h.Perms.Require(ctx, actor, PermModerate); err != nil {
		return err
	}
	var n int
	if err := p.h.DB.QueryRowContext(ctx, `SELECT count(*) FROM conferences_conferences WHERE area_id = ?`, area).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrNotEmpty
	}
	_, err := p.h.DB.ExecContext(ctx, `DELETE FROM conferences_areas WHERE id = ?`, area)
	return err
}

// ---- threads and posts ---------------------------------------------------------

func (p *Plugin) threadIDs(ctx context.Context, where string, args ...any) ([]int64, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT id FROM conferences_threads WHERE `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

const threadCols = `t.id, t.conference_id, t.title, COALESCE(t.author_id, 0), t.created_at, t.last_post_at, t.locked, COALESCE(t.chat_channel_id, 0),
	(SELECT count(*) FROM conferences_posts p WHERE p.thread_id = t.id)`

func (p *Plugin) scanThreads(ctx context.Context, rows *sql.Rows) ([]Thread, error) {
	var out []Thread
	var ids []int64
	for rows.Next() {
		var t Thread
		var created, last string
		if err := rows.Scan(&t.ID, &t.ConferenceID, &t.Title, &t.AuthorID, &created, &last, &t.Locked, &t.ChatChannelID, &t.Posts); err != nil {
			rows.Close()
			return nil, err
		}
		var err error
		if t.CreatedAt, err = store.ParseTime(created); err != nil {
			rows.Close()
			return nil, err
		}
		if t.LastPostAt, err = store.ParseTime(last); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, t)
		ids = append(ids, t.AuthorID)
	}
	rows.Close()
	names, err := p.h.Auth.Usernames(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Author = nameOr(names, out[i].AuthorID)
	}
	return out, nil
}

func nameOr(names map[int64]string, id int64) string {
	if n, ok := names[id]; ok {
		return n
	}
	return "former member"
}

// Threads lists a conference's threads, most recently active first.
func (p *Plugin) Threads(ctx context.Context, user, conf int64) ([]Thread, error) {
	if _, _, err := p.access(ctx, user, conf); err != nil {
		return nil, err
	}
	rows, err := p.h.DB.QueryContext(ctx, `SELECT `+threadCols+` FROM conferences_threads t WHERE t.conference_id = ?
		ORDER BY t.last_post_at DESC, t.id DESC LIMIT ?`, conf, threadLimit)
	if err != nil {
		return nil, fmt.Errorf("conferences: threads: %w", err)
	}
	return p.scanThreads(ctx, rows)
}

// Thread returns a thread the member may read, with its conference.
func (p *Plugin) Thread(ctx context.Context, user, id int64) (Thread, Conference, perm.Set, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT `+threadCols+` FROM conferences_threads t WHERE t.id = ?`, id)
	if err != nil {
		return Thread{}, Conference{}, nil, err
	}
	ts, err := p.scanThreads(ctx, rows)
	if err != nil {
		return Thread{}, Conference{}, nil, err
	}
	if len(ts) == 0 {
		return Thread{}, Conference{}, nil, ErrNotFound
	}
	c, set, err := p.access(ctx, user, ts[0].ConferenceID)
	if err != nil {
		return Thread{}, Conference{}, nil, err
	}
	t := ts[0]
	if err := p.dropClosedChat(ctx, &t); err != nil {
		return Thread{}, Conference{}, nil, err
	}
	return t, c, set, nil
}

// dropClosedChat forgets a thread's chat channel once it no longer exists
// (a moderator closed it from the Chat menu), so the thread offers to
// enable a new one instead of failing to open the old one.
func (p *Plugin) dropClosedChat(ctx context.Context, t *Thread) error {
	if t.ChatChannelID == 0 || p.chat == nil {
		return nil
	}
	_, err := p.chat.Get(ctx, t.ChatChannelID)
	if !errors.Is(err, chat.ErrNotFound) {
		return err
	}
	if _, err := p.h.DB.ExecContext(ctx, `UPDATE conferences_threads SET chat_channel_id = NULL WHERE id = ? AND chat_channel_id = ?`,
		t.ID, t.ChatChannelID); err != nil {
		return fmt.Errorf("conferences: forget closed chat: %w", err)
	}
	p.h.Log.Info("thread chat was closed; reference removed", "thread_id", t.ID, "channel_id", t.ChatChannelID)
	t.ChatChannelID = 0
	return nil
}

// Posts returns a thread's posts, oldest first.
func (p *Plugin) Posts(ctx context.Context, user, thread int64) ([]Post, error) {
	if _, _, _, err := p.Thread(ctx, user, thread); err != nil {
		return nil, err
	}
	rows, err := p.h.DB.QueryContext(ctx, `SELECT id, thread_id, COALESCE(author_id, 0), body, created_at, edited_at
		FROM conferences_posts WHERE thread_id = ? ORDER BY created_at, id`, thread)
	if err != nil {
		return nil, fmt.Errorf("conferences: posts: %w", err)
	}
	var out []Post
	var ids []int64
	for rows.Next() {
		var po Post
		var created string
		var edited sql.NullString
		if err := rows.Scan(&po.ID, &po.ThreadID, &po.AuthorID, &po.Body, &created, &edited); err != nil {
			rows.Close()
			return nil, err
		}
		if po.CreatedAt, err = store.ParseTime(created); err != nil {
			rows.Close()
			return nil, err
		}
		if po.EditedAt, err = store.ScanNullTime(edited); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, po)
		ids = append(ids, po.AuthorID)
	}
	rows.Close()
	names, err := p.h.Auth.Usernames(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Author = nameOr(names, out[i].AuthorID)
		if out[i].Polls, err = p.postPolls(ctx, out[i].ID); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func pollContext(post int64) string { return "conferences:post:" + strconv.FormatInt(post, 10) }

func (p *Plugin) postPolls(ctx context.Context, post int64) ([]int64, error) {
	if p.polls == nil {
		return nil, nil
	}
	return p.polls.ByContext(ctx, pollContext(post))
}

// StartThread creates a thread with its first post.
func (p *Plugin) StartThread(ctx context.Context, user, conf int64, title, body string) (int64, int64, error) {
	c, set, err := p.access(ctx, user, conf)
	if err != nil {
		return 0, 0, err
	}
	if !canPost(set, c) {
		return 0, 0, perm.ErrForbidden
	}
	title, ok := clean(title, MaxTitle, true)
	if !ok {
		return 0, 0, fmt.Errorf("%w: titles are 1 to %d printable characters", ErrInvalid, MaxTitle)
	}
	if body, err = p.checkBody(ctx, body); err != nil {
		return 0, 0, err
	}
	if err := p.checkPostRate(ctx, set, user); err != nil {
		return 0, 0, err
	}
	var thread, post int64
	err = store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		now := store.FormatTime(p.now())
		res, err := tx.ExecContext(ctx, `INSERT INTO conferences_threads (conference_id, title, author_id, created_at, last_post_at) VALUES (?, ?, ?, ?, ?)`,
			conf, title, user, now, now)
		if err != nil {
			return err
		}
		thread, _ = res.LastInsertId()
		res, err = tx.ExecContext(ctx, `INSERT INTO conferences_posts (thread_id, author_id, body, created_at) VALUES (?, ?, ?, ?)`, thread, user, body, now)
		if err != nil {
			return err
		}
		post, _ = res.LastInsertId()
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("conferences: start thread: %w", err)
	}
	p.h.Log.Info("thread started", "thread_id", thread, "conference_id", conf, "author", user)
	return thread, post, nil
}

// Reply adds a post to an unlocked thread.
func (p *Plugin) Reply(ctx context.Context, user, thread int64, body string) (int64, error) {
	t, c, set, err := p.Thread(ctx, user, thread)
	if err != nil {
		return 0, err
	}
	if !canPost(set, c) {
		return 0, perm.ErrForbidden
	}
	if t.Locked {
		return 0, ErrLocked
	}
	if body, err = p.checkBody(ctx, body); err != nil {
		return 0, err
	}
	if err := p.checkPostRate(ctx, set, user); err != nil {
		return 0, err
	}
	var post int64
	err = store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		now := store.FormatTime(p.now())
		res, err := tx.ExecContext(ctx, `INSERT INTO conferences_posts (thread_id, author_id, body, created_at) VALUES (?, ?, ?, ?)`, thread, user, body, now)
		if err != nil {
			return err
		}
		post, _ = res.LastInsertId()
		_, err = tx.ExecContext(ctx, `UPDATE conferences_threads SET last_post_at = ? WHERE id = ?`, now, thread)
		return err
	})
	if err == nil {
		p.notifyAuthor(ctx, user, t)
	}
	return post, err
}

// post loads one post with the permissions to act on it.
func (p *Plugin) post(ctx context.Context, user, id int64) (Post, Thread, perm.Set, error) {
	var po Post
	err := p.h.DB.QueryRowContext(ctx, `SELECT id, thread_id, COALESCE(author_id, 0), body FROM conferences_posts WHERE id = ?`, id).
		Scan(&po.ID, &po.ThreadID, &po.AuthorID, &po.Body)
	if errors.Is(err, sql.ErrNoRows) {
		return Post{}, Thread{}, nil, ErrNotFound
	}
	if err != nil {
		return Post{}, Thread{}, nil, err
	}
	t, _, set, err := p.Thread(ctx, user, po.ThreadID)
	return po, t, set, err
}

// CanEdit reports whether user may edit or delete a post: its author
// (while the thread is unlocked) or a moderator.
func canEdit(set perm.Set, user int64, po Post, t Thread) bool {
	return set.Has(PermModerate) || (po.AuthorID == user && user != 0 && !t.Locked)
}

// Edit replaces a post's body.
func (p *Plugin) Edit(ctx context.Context, user, id int64, body string) error {
	po, t, set, err := p.post(ctx, user, id)
	if err != nil {
		return err
	}
	if !canEdit(set, user, po, t) {
		return perm.ErrForbidden
	}
	if body, err = p.checkBody(ctx, body); err != nil {
		return err
	}
	_, err = p.h.DB.ExecContext(ctx, `UPDATE conferences_posts SET body = ?, edited_at = ? WHERE id = ?`, body, store.FormatTime(p.now()), id)
	return err
}

// checkPostRate refuses a post once user has made the most allowed in the
// last hour. Moderators are not limited.
func (p *Plugin) checkPostRate(ctx context.Context, set perm.Set, user int64) error {
	if set.Has(PermModerate) {
		return nil
	}
	max := defaultMaxPostsPerHour
	if v, err := p.h.Settings.Get(ctx, setMaxPostsPerHour); err == nil {
		if n, err := strconv.Atoi(v); err == nil {
			max = n
		}
	}
	var n int
	if err := p.h.DB.QueryRowContext(ctx, `SELECT count(*) FROM conferences_posts WHERE author_id = ? AND created_at > ?`,
		user, store.FormatTime(p.now().Add(-time.Hour))).Scan(&n); err != nil {
		return fmt.Errorf("conferences: count recent posts: %w", err)
	}
	if n >= max {
		p.h.Log.Info("post refused: hourly limit", "user_id", user, "limit", max)
		return fmt.Errorf("%w: you have reached the limit of posts an hour (%d); please wait a while", ErrInvalid, max)
	}
	return nil
}

// DeletePost deletes a reply. The first post deletes the whole thread when
// a moderator deletes it or nobody else has replied; once others have,
// their replies are not the author's to delete, so the author's first post
// is blanked instead (as erasure does) and the thread stays.
func (p *Plugin) DeletePost(ctx context.Context, user, id int64) (threadDeleted bool, err error) {
	po, t, set, err := p.post(ctx, user, id)
	if err != nil {
		return false, err
	}
	if !canEdit(set, user, po, t) {
		return false, perm.ErrForbidden
	}
	var first int64
	if err := p.h.DB.QueryRowContext(ctx, `SELECT id FROM conferences_posts WHERE thread_id = ? ORDER BY created_at, id LIMIT 1`, t.ID).Scan(&first); err != nil {
		return false, err
	}
	if first == id {
		whole, err := p.firstPostDeletesThread(ctx, set, user, t.ID, id)
		if err != nil {
			return false, err
		}
		if whole {
			return true, p.deleteThread(ctx, t.ID)
		}
		return false, p.blankFirstPost(ctx, t.ID, id)
	}
	if p.polls != nil {
		if err := p.polls.DeleteContext(ctx, pollContext(id)); err != nil {
			return false, err
		}
	}
	_, err = p.h.DB.ExecContext(ctx, `DELETE FROM conferences_posts WHERE id = ?`, id)
	return false, err
}

// firstPostDeletesThread reports whether deleting first, the thread's
// first post, deletes the whole thread for user: a moderator, or nobody
// else has replied. Otherwise the post is blanked.
func (p *Plugin) firstPostDeletesThread(ctx context.Context, set perm.Set, user, thread, first int64) (bool, error) {
	if set.Has(PermModerate) {
		return true, nil
	}
	var others int
	err := p.h.DB.QueryRowContext(ctx, `SELECT count(*) FROM conferences_posts WHERE thread_id = ? AND id <> ? AND (author_id IS NULL OR author_id <> ?)`,
		thread, first, user).Scan(&others)
	return others == 0, err
}

// blankFirstPost removes the author's own content from a thread others
// have replied to: the first post's text, the title and any poll on it.
func (p *Plugin) blankFirstPost(ctx context.Context, thread, id int64) error {
	if p.polls != nil {
		if err := p.polls.DeleteContext(ctx, pollContext(id)); err != nil {
			return err
		}
	}
	return store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE conferences_posts SET body = ?, edited_at = ? WHERE id = ?`, RemovedBody, store.FormatTime(p.now()), id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE conferences_threads SET title = ? WHERE id = ?`, AuthorRemovedTitle, thread); err != nil {
			return err
		}
		p.h.Log.Info("first post blanked by its author", "thread_id", thread)
		return nil
	})
}

// DeleteThread deletes a thread (moderators, or its author if nobody else
// has replied — handled through DeletePost on the first post).
func (p *Plugin) DeleteThread(ctx context.Context, user, thread int64) error {
	if _, _, set, err := p.Thread(ctx, user, thread); err != nil {
		return err
	} else if !set.Has(PermModerate) {
		return perm.ErrForbidden
	}
	return p.deleteThread(ctx, thread)
}

func (p *Plugin) deleteThread(ctx context.Context, thread int64) error {
	if err := p.cleanupThread(ctx, thread); err != nil {
		return err
	}
	_, err := p.h.DB.ExecContext(ctx, `DELETE FROM conferences_threads WHERE id = ?`, thread)
	if err == nil {
		p.h.Log.Info("thread deleted", "thread_id", thread)
	}
	return err
}

// cleanupThread removes what other plugins hold for a thread: polls on its
// posts and its chat channel.
func (p *Plugin) cleanupThread(ctx context.Context, thread int64) error {
	if p.polls != nil {
		rows, err := p.h.DB.QueryContext(ctx, `SELECT id FROM conferences_posts WHERE thread_id = ?`, thread)
		if err != nil {
			return err
		}
		var posts []int64
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			posts = append(posts, id)
		}
		rows.Close()
		for _, id := range posts {
			if err := p.polls.DeleteContext(ctx, pollContext(id)); err != nil {
				return err
			}
		}
	}
	if p.chat != nil {
		return p.chat.DestroyContext(ctx, threadChatContext(thread))
	}
	return nil
}

const threadChatPrefix = "conferences:thread:"

// maxChatName is the chat plugin's channel name limit.
const maxChatName = 32

// chatNames returns channel names to try for a thread's chat, most
// readable first: "<conference>-<title words>", then the same with the
// thread ID to make it unique, then "thread-<id>". Each is a valid chat
// name: lowercase letters, digits and '-', starting with a letter.
func chatNames(confSlug, title string, thread int64) []string {
	words := strings.FieldsFunc(strings.ToLower(title), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	})
	base := strings.Trim(confSlug, "-")
	if base == "" || base[0] < 'a' || base[0] > 'z' {
		base = "c" + base
	}
	fit := func(suffix string) string {
		name := base
		for _, w := range words {
			if len(name)+1+len(w)+len(suffix) > maxChatName {
				break
			}
			name += "-" + w
		}
		if len(name)+len(suffix) > maxChatName {
			name = strings.TrimRight(name[:maxChatName-len(suffix)], "-")
		}
		return name + suffix
	}
	id := strconv.FormatInt(thread, 10)
	return []string{fit(""), fit("-" + id), "thread-" + id}
}

func threadChatContext(thread int64) string {
	return threadChatPrefix + strconv.FormatInt(thread, 10)
}

// chatAccess lets into a thread's chat exactly the members who can read the
// thread, so the chat follows the conference's groups.
func (p *Plugin) chatAccess(ctx context.Context, user int64, context string) (bool, error) {
	thread, err := strconv.ParseInt(strings.TrimPrefix(context, threadChatPrefix), 10, 64)
	if err != nil {
		return false, nil
	}
	_, _, _, err = p.Thread(ctx, user, thread)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// SetLocked locks or unlocks a thread (moderators).
func (p *Plugin) SetLocked(ctx context.Context, user, thread int64, locked bool) error {
	if _, _, set, err := p.Thread(ctx, user, thread); err != nil {
		return err
	} else if !set.Has(PermModerate) {
		return perm.ErrForbidden
	}
	_, err := p.h.DB.ExecContext(ctx, `UPDATE conferences_threads SET locked = ? WHERE id = ?`, locked, thread)
	return err
}

// EnableChat creates the thread's chat channel (moderators). Only members
// who can read the conference can join it.
func (p *Plugin) EnableChat(ctx context.Context, user, thread int64) (int64, error) {
	if p.chat == nil {
		return 0, fmt.Errorf("%w: chat is not installed", ErrInvalid)
	}
	t, c, set, err := p.Thread(ctx, user, thread)
	if err != nil {
		return 0, err
	}
	if !set.Has(PermModerate) {
		return 0, perm.ErrForbidden
	}
	if t.ChatChannelID != 0 {
		return t.ChatChannelID, nil
	}
	// Titles (MaxTitle) fit the chat topic limit (chat.MaxTopic).
	// Access follows the conference's groups through chatAccess.
	var id int64
	for _, name := range chatNames(c.Slug, t.Title, thread) {
		id, err = p.chat.EnsureThreadChannel(ctx, threadChatContext(thread), name, t.Title)
		if !errors.Is(err, chat.ErrExists) {
			break
		}
	}
	if err != nil {
		return 0, err
	}
	_, err = p.h.DB.ExecContext(ctx, `UPDATE conferences_threads SET chat_channel_id = ? WHERE id = ?`, id, thread)
	return id, err
}

// canAddPoll checks that user may attach a poll to post: its author (or a
// moderator) holding polls.create.
func (p *Plugin) canAddPoll(ctx context.Context, user, post int64) error {
	po, t, set, err := p.post(ctx, user, post)
	if err != nil {
		return err
	}
	if p.polls == nil {
		return fmt.Errorf("%w: polls are not installed", ErrInvalid)
	}
	if !canEdit(set, user, po, t) || !set.Has(polls.PermCreate) {
		return perm.ErrForbidden
	}
	return nil
}
