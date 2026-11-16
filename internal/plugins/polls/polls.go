// Package polls is the core Polls plugin (docs/DESIGN.md §12): single or
// multiple choice polls, anonymous by default, with results, pinned polls,
// and an API other plugins (Conferences) use to attach polls to content.
package polls

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Permissions.
const (
	PermVote   = "polls.vote"
	PermCreate = "polls.create"
	PermManage = "polls.manage" // pin, close or delete any poll
)

// Limits.
const (
	MaxQuestion   = 200
	MaxOption     = 100
	MinOptions    = 2
	MaxOptions    = 10
	MaxOpenDays   = 365
	listLimit     = 100
	pluginVersion = "1.0.0"
)

// Errors.
var (
	ErrNotFound = errors.New("poll not found")
	ErrInvalid  = errors.New("invalid poll")
	ErrClosed   = errors.New("this poll is closed")
	ErrBadVote  = errors.New("invalid vote")
)

var contextPattern = regexp.MustCompile(`^[a-z][a-z0-9]*:[a-z0-9:_-]{1,64}$`)

// Plugin implements plugin.Plugin.
type Plugin struct {
	h   *plugin.Host
	now func() time.Time
}

// New returns the Polls plugin.
func New() *Plugin { return &Plugin{now: time.Now} }

var _ plugin.Plugin = (*Plugin)(nil)

// Manifest implements plugin.Plugin.
func (p *Plugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID: "polls", Name: "Polls", Version: pluginVersion,
		Description: "Polls and voting",
		Permissions: []plugin.Permission{
			{Name: PermVote, Description: "Vote in polls", DefaultGroups: []string{perm.GroupMember, perm.GroupModerator}},
			{Name: PermCreate, Description: "Create polls", DefaultGroups: []string{perm.GroupMember, perm.GroupModerator}},
			{Name: PermManage, Description: "Pin, close and delete any poll", DefaultGroups: []string{perm.GroupModerator}},
		},
		Migrations: []store.Migration{{Version: 1, Name: "polls", SQL: `
			-- context is '' for polls in the Polls menu, or the owner of an
			-- attached poll, e.g. 'conferences:post:42'.
			CREATE TABLE polls_polls (
				id         INTEGER PRIMARY KEY,
				creator_id INTEGER REFERENCES users (id) ON DELETE SET NULL,
				question   TEXT    NOT NULL,
				multi      INTEGER NOT NULL CHECK (multi IN (0, 1)),
				anonymous  INTEGER NOT NULL CHECK (anonymous IN (0, 1)),
				pinned     INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
				context    TEXT    NOT NULL DEFAULT '',
				created_at TEXT    NOT NULL,
				closes_at  TEXT,
				closed_at  TEXT
			) STRICT;
			CREATE INDEX polls_polls_context ON polls_polls (context, pinned, created_at);

			CREATE TABLE polls_options (
				id       INTEGER PRIMARY KEY,
				poll_id  INTEGER NOT NULL REFERENCES polls_polls (id) ON DELETE CASCADE,
				position INTEGER NOT NULL,
				label    TEXT    NOT NULL
			) STRICT;
			CREATE INDEX polls_options_poll ON polls_options (poll_id, position);

			-- user_id becomes NULL when an account is deleted, so totals are
			-- kept but the vote is no longer linked to anyone.
			CREATE TABLE polls_votes (
				poll_id    INTEGER NOT NULL REFERENCES polls_polls (id) ON DELETE CASCADE,
				option_id  INTEGER NOT NULL REFERENCES polls_options (id) ON DELETE CASCADE,
				user_id    INTEGER REFERENCES users (id) ON DELETE SET NULL,
				created_at TEXT    NOT NULL,
				UNIQUE (option_id, user_id)
			) STRICT;
			CREATE INDEX polls_votes_poll_user ON polls_votes (poll_id, user_id);`}},
		MenuItems: []plugin.MenuItem{{Key: "main", Label: "Polls", Help: "Vote and see results", Run: p.run}},
	}
}

// Init implements plugin.Plugin.
func (p *Plugin) Init(_ context.Context, h *plugin.Host) error {
	p.h = h
	return nil
}

// Spec describes a new poll.
type Spec struct {
	Question  string
	Options   []string
	Multi     bool          // several options may be chosen
	Named     bool          // voters' names are shown with results
	ClosesIn  time.Duration // 0 = open until closed by hand
	Pinned    bool          // requires polls.manage
	Context   string        // "" or "<plugin>:<key>" for attached polls
	CreatorID int64
}

// Option is a poll choice with its tally.
type Option struct {
	ID     int64
	Label  string
	Votes  int
	Voters []string // only for named polls
}

// Poll is a poll as seen by one member.
type Poll struct {
	ID        int64
	CreatorID int64
	Creator   string
	Question  string
	Multi     bool
	Anonymous bool
	Pinned    bool
	Context   string
	CreatedAt time.Time
	ClosesAt  *time.Time
	ClosedAt  *time.Time
	Options   []Option
	Voters    int     // members who voted
	MyVotes   []int64 // option IDs the viewer chose
}

// Closed reports whether voting has ended at now.
func (p Poll) Closed(now time.Time) bool {
	return p.ClosedAt != nil || (p.ClosesAt != nil && !now.Before(*p.ClosesAt))
}

func cleanLabel(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	n := utf8.RuneCountInString(s)
	return s, n > 0 && n <= max && term.Sanitize(s, false) == s
}

// Create makes a poll and returns its ID.
func (p *Plugin) Create(ctx context.Context, s Spec) (int64, error) {
	set, err := p.h.Perms.Permissions(ctx, s.CreatorID)
	if err != nil {
		return 0, err
	}
	if !set.Has(PermCreate) || (s.Pinned && !set.Has(PermManage)) {
		return 0, perm.ErrForbidden
	}
	q, ok := cleanLabel(s.Question, MaxQuestion)
	if !ok {
		return 0, fmt.Errorf("%w: the question must be 1 to %d printable characters", ErrInvalid, MaxQuestion)
	}
	var opts []string
	for _, o := range s.Options {
		if strings.TrimSpace(o) == "" {
			continue
		}
		l, ok := cleanLabel(o, MaxOption)
		if !ok {
			return 0, fmt.Errorf("%w: each option must be at most %d printable characters", ErrInvalid, MaxOption)
		}
		if slices.ContainsFunc(opts, func(x string) bool { return strings.EqualFold(x, l) }) {
			return 0, fmt.Errorf("%w: option %q is listed twice", ErrInvalid, l)
		}
		opts = append(opts, l)
	}
	if len(opts) < MinOptions || len(opts) > MaxOptions {
		return 0, fmt.Errorf("%w: a poll needs %d to %d options", ErrInvalid, MinOptions, MaxOptions)
	}
	if s.ClosesIn < 0 || s.ClosesIn > MaxOpenDays*24*time.Hour {
		return 0, fmt.Errorf("%w: a poll can stay open for at most %d days", ErrInvalid, MaxOpenDays)
	}
	if s.Context != "" && !contextPattern.MatchString(s.Context) {
		return 0, fmt.Errorf("%w: bad context", ErrInvalid)
	}
	now := p.now()
	var closes any
	if s.ClosesIn > 0 {
		closes = store.FormatTime(now.Add(s.ClosesIn))
	}
	var id int64
	err = store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `INSERT INTO polls_polls (creator_id, question, multi, anonymous, pinned, context, created_at, closes_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, s.CreatorID, q, s.Multi, !s.Named, s.Pinned, s.Context, store.FormatTime(now), closes)
		if err != nil {
			return fmt.Errorf("polls: create: %w", err)
		}
		id, _ = res.LastInsertId()
		for i, o := range opts {
			if _, err := tx.ExecContext(ctx, `INSERT INTO polls_options (poll_id, position, label) VALUES (?, ?, ?)`, id, i+1, o); err != nil {
				return fmt.Errorf("polls: option: %w", err)
			}
		}
		return nil
	})
	if err == nil {
		p.h.Log.Info("poll created", "poll_id", id, "creator", s.CreatorID, "context", s.Context)
	}
	return id, err
}

// Get returns a poll with its tallies and the viewer's own votes. Voter
// names are included only for named polls.
func (p *Plugin) Get(ctx context.Context, viewer, id int64) (Poll, error) {
	var pl Poll
	var creator sql.NullInt64
	var created string
	var closes, closed sql.NullString
	err := p.h.DB.QueryRowContext(ctx, `SELECT id, creator_id, question, multi, anonymous, pinned, context, created_at, closes_at, closed_at
		FROM polls_polls WHERE id = ?`, id).Scan(&pl.ID, &creator, &pl.Question, &pl.Multi, &pl.Anonymous, &pl.Pinned, &pl.Context, &created, &closes, &closed)
	if errors.Is(err, sql.ErrNoRows) {
		return Poll{}, ErrNotFound
	}
	if err != nil {
		return Poll{}, fmt.Errorf("polls: get: %w", err)
	}
	pl.CreatorID = creator.Int64
	if pl.CreatedAt, err = store.ParseTime(created); err != nil {
		return Poll{}, err
	}
	if pl.ClosesAt, err = store.ScanNullTime(closes); err != nil {
		return Poll{}, err
	}
	if pl.ClosedAt, err = store.ScanNullTime(closed); err != nil {
		return Poll{}, err
	}
	names, err := p.h.Auth.Usernames(ctx, []int64{pl.CreatorID})
	if err != nil {
		return Poll{}, err
	}
	pl.Creator = names[pl.CreatorID]
	if pl.Creator == "" {
		pl.Creator = "former member"
	}

	rows, err := p.h.DB.QueryContext(ctx, `SELECT o.id, o.label, count(v.option_id) FROM polls_options o
		LEFT JOIN polls_votes v ON v.option_id = o.id WHERE o.poll_id = ? GROUP BY o.id ORDER BY o.position`, id)
	if err != nil {
		return Poll{}, err
	}
	for rows.Next() {
		var o Option
		if err := rows.Scan(&o.ID, &o.Label, &o.Votes); err != nil {
			rows.Close()
			return Poll{}, err
		}
		pl.Options = append(pl.Options, o)
	}
	rows.Close()

	// Votes of deleted accounts have no user; each such row counts as one
	// voter (slightly over-counting multi-choice votes of deleted accounts).
	if err := p.h.DB.QueryRowContext(ctx, `SELECT count(DISTINCT COALESCE(user_id, -rowid)) FROM polls_votes WHERE poll_id = ?`, id).Scan(&pl.Voters); err != nil {
		return Poll{}, err
	}
	rows, err = p.h.DB.QueryContext(ctx, `SELECT option_id FROM polls_votes WHERE poll_id = ? AND user_id = ?`, id, viewer)
	if err != nil {
		return Poll{}, err
	}
	for rows.Next() {
		var oid int64
		if err := rows.Scan(&oid); err != nil {
			rows.Close()
			return Poll{}, err
		}
		pl.MyVotes = append(pl.MyVotes, oid)
	}
	rows.Close()

	if !pl.Anonymous {
		if err := p.loadVoters(ctx, &pl); err != nil {
			return Poll{}, err
		}
	}
	return pl, nil
}

func (p *Plugin) loadVoters(ctx context.Context, pl *Poll) error {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT option_id, user_id FROM polls_votes WHERE poll_id = ? AND user_id IS NOT NULL`, pl.ID)
	if err != nil {
		return err
	}
	byOption := map[int64][]int64{}
	var ids []int64
	for rows.Next() {
		var oid, uid int64
		if err := rows.Scan(&oid, &uid); err != nil {
			rows.Close()
			return err
		}
		byOption[oid] = append(byOption[oid], uid)
		ids = append(ids, uid)
	}
	rows.Close()
	names, err := p.h.Auth.Usernames(ctx, ids)
	if err != nil {
		return err
	}
	for i, o := range pl.Options {
		for _, uid := range byOption[o.ID] {
			if n, ok := names[uid]; ok {
				pl.Options[i].Voters = append(pl.Options[i].Voters, n)
			}
		}
		slices.Sort(pl.Options[i].Voters)
	}
	return nil
}

// Vote records (or replaces) user's choice while the poll is open.
func (p *Plugin) Vote(ctx context.Context, user, pollID int64, options []int64) error {
	if err := p.h.Perms.Require(ctx, user, PermVote); err != nil {
		return err
	}
	pl, err := p.Get(ctx, user, pollID)
	if err != nil {
		return err
	}
	if pl.Closed(p.now()) {
		return ErrClosed
	}
	slices.Sort(options)
	options = slices.Compact(options)
	switch {
	case pl.Multi && len(options) == 0:
		return fmt.Errorf("%w: choose at least one option", ErrBadVote)
	case !pl.Multi && len(options) != 1:
		return fmt.Errorf("%w: choose exactly one option", ErrBadVote)
	}
	for _, o := range options {
		if !slices.ContainsFunc(pl.Options, func(x Option) bool { return x.ID == o }) {
			return fmt.Errorf("%w: unknown option", ErrBadVote)
		}
	}
	err = store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM polls_votes WHERE poll_id = ? AND user_id = ?`, pollID, user); err != nil {
			return err
		}
		now := store.FormatTime(p.now())
		for _, o := range options {
			if _, err := tx.ExecContext(ctx, `INSERT INTO polls_votes (poll_id, option_id, user_id, created_at) VALUES (?, ?, ?, ?)`, pollID, o, user, now); err != nil {
				return fmt.Errorf("polls: vote: %w", err)
			}
		}
		return nil
	})
	if err == nil {
		p.h.Log.Info("vote recorded", "poll_id", pollID) // never who voted for what
	}
	return err
}

// CanSeeResults reports whether viewer may see tallies: after voting, once
// closed, or as the creator or a poll manager.
func (p *Plugin) CanSeeResults(pl Poll, viewer int64, set perm.Set) bool {
	return len(pl.MyVotes) > 0 || pl.Closed(p.now()) || pl.CreatorID == viewer || set.Has(PermManage)
}

// canManage reports whether actor may close, pin or delete pl.
func (p *Plugin) canManage(ctx context.Context, actor int64, pl Poll, pin bool) error {
	set, err := p.h.Perms.Permissions(ctx, actor)
	if err != nil {
		return err
	}
	if set.Has(PermManage) || (!pin && pl.CreatorID == actor && pl.CreatorID != 0) {
		return nil
	}
	return perm.ErrForbidden
}

// Close ends voting. The creator or a poll manager may close a poll.
func (p *Plugin) Close(ctx context.Context, actor, id int64) error {
	pl, err := p.Get(ctx, actor, id)
	if err != nil {
		return err
	}
	if err := p.canManage(ctx, actor, pl, false); err != nil {
		return err
	}
	_, err = p.h.DB.ExecContext(ctx, `UPDATE polls_polls SET closed_at = ? WHERE id = ? AND closed_at IS NULL`, store.FormatTime(p.now()), id)
	return err
}

// SetPinned pins or unpins a poll (poll managers only).
func (p *Plugin) SetPinned(ctx context.Context, actor, id int64, pinned bool) error {
	pl, err := p.Get(ctx, actor, id)
	if err != nil {
		return err
	}
	if err := p.canManage(ctx, actor, pl, true); err != nil {
		return err
	}
	_, err = p.h.DB.ExecContext(ctx, `UPDATE polls_polls SET pinned = ? WHERE id = ?`, pinned, id)
	return err
}

// Delete removes a poll and its votes. The creator or a poll manager may
// delete a poll.
func (p *Plugin) Delete(ctx context.Context, actor, id int64) error {
	pl, err := p.Get(ctx, actor, id)
	if err != nil {
		return err
	}
	if err := p.canManage(ctx, actor, pl, false); err != nil {
		return err
	}
	_, err = p.h.DB.ExecContext(ctx, `DELETE FROM polls_polls WHERE id = ?`, id)
	if err == nil {
		p.h.Log.Info("poll deleted", "poll_id", id, "actor", actor)
	}
	return err
}

// Summary is a poll in a listing.
type Summary struct {
	ID       int64
	Question string
	Pinned   bool
	Closed   bool
}

// List returns the Polls-menu polls (context ""): pinned first, then
// newest. open selects open (true) or closed (false) polls.
func (p *Plugin) List(ctx context.Context, open bool) ([]Summary, error) {
	now := store.FormatTime(p.now())
	cond := `closed_at IS NULL AND (closes_at IS NULL OR closes_at > ?)`
	if !open {
		cond = `NOT (` + cond + `)`
	}
	rows, err := p.h.DB.QueryContext(ctx, `SELECT id, question, pinned FROM polls_polls WHERE context = '' AND `+cond+`
		ORDER BY pinned DESC, created_at DESC, id DESC LIMIT ?`, now, listLimit)
	if err != nil {
		return nil, fmt.Errorf("polls: list: %w", err)
	}
	defer rows.Close()
	var out []Summary
	for rows.Next() {
		s := Summary{Closed: !open}
		if err := rows.Scan(&s.ID, &s.Question, &s.Pinned); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// DeleteContext deletes every poll attached to context, for plugins
// removing the content the polls belonged to. It performs no permission
// check: the calling plugin has already checked its own.
func (p *Plugin) DeleteContext(ctx context.Context, pollContext string) error {
	if pollContext == "" {
		return fmt.Errorf("%w: empty context", ErrInvalid)
	}
	_, err := p.h.DB.ExecContext(ctx, `DELETE FROM polls_polls WHERE context = ?`, pollContext)
	return err
}

// ByContext returns the IDs of polls attached to context, oldest first.
func (p *Plugin) ByContext(ctx context.Context, pollContext string) ([]int64, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT id FROM polls_polls WHERE context = ? ORDER BY id`, pollContext)
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
