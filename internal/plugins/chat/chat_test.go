package chat

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/plugintest"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

type fixture struct {
	*plugintest.Env
	p                      *Plugin
	alice, bob, carol, mod int64
}

func setup(t *testing.T) *fixture {
	t.Helper()
	p := New()
	e := plugintest.New(t, p)
	return &fixture{Env: e, p: p, alice: e.User("alice"), bob: e.User("bob"), carol: e.User("carol"), mod: e.User("mod1", perm.GroupModerator)}
}

func (f *fixture) user(t *testing.T, id int64) auth.User {
	u, err := f.Auth.UserByID(f.Ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAccessRules(t *testing.T) {
	f := setup(t)
	lobby, err := f.p.ByName(f.Ctx, "#Lobby")
	if err != nil || lobby.Kind != KindPersistent || lobby.Tag() != "[C]" {
		t.Fatalf("seeded lobby = %+v, %v", lobby, err)
	}
	f.Perms.Registry().Register("club.member", "Club")
	modGroup, err := f.Perms.GroupByName(f.Ctx, perm.GroupModerator)
	if err != nil {
		t.Fatal(err)
	}
	staff, err := f.p.Create(f.Ctx, f.mod, NewChannel{Name: "staff", Kind: KindPersistent, Groups: []int64{modGroup.ID}, RetentionDays: 30})
	if err != nil {
		t.Fatal(err)
	}
	priv, err := f.p.createAdHoc(f.Ctx, f.alice, "plans", "", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Create(f.Ctx, f.alice, NewChannel{Name: "mine", Kind: KindPersistent}); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member creating a persistent channel err = %v", err)
	}
	if _, err := f.p.createAdHoc(f.Ctx, f.alice, "plans", "", ""); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate name err = %v", err)
	}
	if _, err := f.p.createAdHoc(f.Ctx, f.alice, "Bad Name", "", ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad name err = %v", err)
	}

	sc, _ := f.p.Get(f.Ctx, staff)
	pc, _ := f.p.Get(f.Ctx, priv)
	tests := []struct {
		name string
		user int64
		ch   Channel
		want bool
	}{
		{"member in lobby", f.carol, lobby, true},
		{"member in staff channel", f.carol, sc, false},
		{"moderator in staff channel", f.mod, sc, true},
		{"creator in private chat", f.alice, pc, true},
		{"invited in private chat", f.bob, pc, true},
		{"uninvited in private chat", f.carol, pc, false},
		{"moderator in private chat", f.mod, pc, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, err := f.p.CanAccess(f.Ctx, tt.user, tt.ch); err != nil || got != tt.want {
				t.Errorf("CanAccess = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
	chans, _ := f.p.Accessible(f.Ctx, f.carol)
	if len(chans) != 1 || chans[0].Name != "lobby" {
		t.Errorf("carol's channels = %+v", chans)
	}

	// Revoking chat.use removes access everywhere.
	g, _ := f.Perms.GroupByName(f.Ctx, perm.GroupMember)
	f.Perms.Revoke(f.Ctx, f.Admin, g.ID, PermUse)
	if ok, _ := f.p.CanAccess(f.Ctx, f.carol, lobby); ok {
		t.Error("access without chat.use")
	}
}

func TestSubmitCommandsAndKick(t *testing.T) {
	f := setup(t)
	alice, bob, carol := f.user(t, f.alice), f.user(t, f.bob), f.user(t, f.carol)
	id, _ := f.p.createAdHoc(f.Ctx, f.alice, "plans", "Saturday", "bob")
	s := fakeSession{}

	bm := f.p.hub.join(id, bob.ID, bob.Username)
	f.p.hub.join(id, alice.ID, alice.Username)

	text := func(lines []tui.Line) string {
		var out []string
		for _, l := range lines {
			out = append(out, l.Plain())
		}
		return strings.Join(out, "\n")
	}
	tests := []struct {
		name    string
		by      auth.User
		input   string
		want    string
		leave   bool
		switchs bool
	}{
		{"who", alice, "/who", "In #plans: alice, bob.", false, false},
		{"topic show", bob, "/topic", "Topic: Saturday", false, false},
		{"topic by invitee refused", bob, "/topic Sunday", "permission", false, false},
		{"topic by creator", alice, "/topic Sunday", "", false, false},
		{"invite", alice, "/invite carol", "carol can now join", false, false},
		{"invite unknown", alice, "/invite ghost", "no member called", false, false},
		{"kick self refused", alice, "/kick alice", "cannot kick yourself", false, false},
		{"kick by invitee refused", bob, "/kick alice", "permission", false, false},
		{"unknown command", bob, "/dance", "Unknown command /dance", false, false},
		{"help", bob, "/help", "/createchat NAME", false, false},
		{"join a channel", bob, "/join lobby", "", true, true},
		{"join hidden private chat", carol, "/join plans", "", true, true}, // carol was invited above
		{"quit", bob, "/quit", "", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fb, leave, next := f.p.submit(f.Ctx, s, tt.by, id, tt.input)
			if got := text(fb); tt.want != "" && !strings.Contains(got, tt.want) {
				t.Errorf("feedback = %q, want %q", got, tt.want)
			}
			if leave != tt.leave || (next != 0) != tt.switchs {
				t.Errorf("leave = %v, next = %d", leave, next)
			}
		})
	}

	// A message reaches everyone in the room and is logged.
	f.p.submit(f.Ctx, s, alice, id, "see you there")
	got := drain(bm.out)
	if !strings.Contains(got, "alice: see you there") || !strings.Contains(got, "changed the topic to: Sunday") {
		t.Errorf("bob received %q", got)
	}
	c, _ := f.p.Get(f.Ctx, id)
	hist, _ := f.p.History(f.Ctx, c, 10, time.Time{}, time.Time{})
	if len(hist) != 2 || hist[1].Body != "see you there" || hist[1].Name != "alice" {
		t.Errorf("history = %+v", hist)
	}

	// Kicking ends bob's view and withdraws his invitation.
	if fb, _, _ := f.p.submit(f.Ctx, s, alice, id, "/kick bob"); len(fb) != 0 {
		t.Errorf("kick feedback = %q", text(fb))
	}
	if !closedWith(bm.out, "You were removed") {
		t.Error("kicked member's view was not ended")
	}
	if ok, _ := f.p.CanAccess(f.Ctx, bob.ID, c); ok {
		t.Error("kicked member can still enter the private chat")
	}

	// /destroychat by the creator closes the chat for everyone.
	cm := f.p.hub.join(id, carol.ID, carol.Username)
	if _, leave, _ := f.p.submit(f.Ctx, s, alice, id, "/destroychat"); !leave {
		t.Error("destroychat did not leave")
	}
	if !closedWith(cm.out, "This chat was closed.") {
		t.Error("members not removed when the chat was closed")
	}
	if _, err := f.p.Get(f.Ctx, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("chat still exists: %v", err)
	}
}

func drain(ch <-chan tui.Line) string {
	var out []string
	for {
		select {
		case l, ok := <-ch:
			if !ok {
				return strings.Join(out, "\n")
			}
			out = append(out, l.Plain())
		default:
			return strings.Join(out, "\n")
		}
	}
}

func closedWith(ch <-chan tui.Line, want string) bool {
	got := ""
	for l := range ch {
		got += l.Plain() + "\n"
	}
	return strings.Contains(got, want)
}

func TestFloodControl(t *testing.T) {
	h := newHub()
	now := time.Now()
	for i := range floodLines {
		if !h.allow(1, now.Add(time.Duration(i)*time.Millisecond)) {
			t.Fatalf("message %d refused", i+1)
		}
	}
	if h.allow(1, now.Add(time.Second)) {
		t.Error("flood not limited")
	}
	if !h.allow(2, now) {
		t.Error("limit shared between members")
	}
	if !h.allow(1, now.Add(floodWindow+time.Second)) {
		t.Error("still limited after the window")
	}
}

func TestRetentionAndSFTP(t *testing.T) {
	f := setup(t)
	alice := f.user(t, f.alice)
	lobby, _ := f.p.ByName(f.Ctx, "lobby")
	old := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	recent := time.Now().UTC().Truncate(time.Second)
	f.p.record(f.Ctx, lobby, alice.ID, "message", "ancient", old)
	f.p.record(f.Ctx, lobby, alice.ID, "message", "fresh", recent)

	fs := &logFS{p: f.p}
	carol := sftpd.User{ID: f.carol, Name: "carol"}
	days, err := fs.List(f.Ctx, carol, []string{"lobby"})
	if err != nil || len(days) != 2 || days[0].Name != "20260101.log" {
		t.Fatalf("days = %+v, %v", days, err)
	}
	data, _, err := fs.Read(f.Ctx, carol, []string{"lobby", "20260101.log"})
	if err != nil || !strings.Contains(string(data), "[10:00:00] alice: ancient") {
		t.Errorf("log = %q, %v", data, err)
	}
	if _, _, err := fs.Read(f.Ctx, carol, []string{"LOBBY", "20260101.log"}); !errors.Is(err, sftpd.ErrNotExist) {
		t.Errorf("case-variant path err = %v", err)
	}
	priv, _ := f.p.createAdHoc(f.Ctx, f.alice, "secret", "", "")
	pc, _ := f.p.Get(f.Ctx, priv)
	f.p.record(f.Ctx, pc, alice.ID, "message", "hidden", recent)
	if _, err := fs.List(f.Ctx, carol, []string{"secret"}); !errors.Is(err, sftpd.ErrNotExist) {
		t.Errorf("uninvited member listing a private log err = %v", err)
	}

	// The default 90-day retention purges the January message.
	n, err := f.p.PurgeExpired(f.Ctx)
	if err != nil || n != 1 {
		t.Fatalf("purged = %d, %v; want 1", n, err)
	}
	// Retention 0 stops logging and deletes the log.
	if err := f.p.SetRetention(f.Ctx, f.alice, lobby, 0); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member changing retention err = %v", err)
	}
	if err := f.p.SetRetention(f.Ctx, f.mod, lobby, 0); err != nil {
		t.Fatal(err)
	}
	lobby, _ = f.p.Get(f.Ctx, lobby.ID)
	f.p.record(f.Ctx, lobby, alice.ID, "message", "unlogged", recent)
	if hist, _ := f.p.History(f.Ctx, lobby, 10, time.Time{}, time.Time{}); len(hist) != 0 {
		t.Errorf("unlogged channel has history %+v", hist)
	}
	if root, _ := fs.List(f.Ctx, carol, nil); len(root) != 0 {
		t.Errorf("unlogged channel listed over SFTP: %+v", root)
	}
}

func TestThreadChannel(t *testing.T) {
	f := setup(t)
	id, err := f.p.EnsureThreadChannel(f.Ctx, "conferences:thread:7", "t-7-hello", "Hello")
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.p.EnsureThreadChannel(f.Ctx, "conferences:thread:7", "t-7-hello", "Hello")
	if err != nil || again != id {
		t.Errorf("second ensure = %d, %v; want %d", again, err, id)
	}
	c, _ := f.p.Get(f.Ctx, id)
	if c.Kind != KindThread || c.Tag() != "[T]" {
		t.Errorf("thread channel = %+v", c)
	}
}

// fakeSession is enough of plugin.Session for submit.
type fakeSession struct{ plugin.Session }

func (fakeSession) Log() *slog.Logger { return slog.New(slog.DiscardHandler) }

func TestChannelGroups(t *testing.T) {
	f := setup(t)
	staffID, err := f.Perms.CreateGroup(f.Ctx, f.Admin, "staff", "Staff")
	if err != nil {
		t.Fatal(err)
	}
	modGroup, _ := f.Perms.GroupByName(f.Ctx, perm.GroupModerator)
	dave := f.User("dave", perm.GroupMember, "staff")
	both, err := f.p.Create(f.Ctx, f.mod, NewChannel{Name: "ops", Kind: KindPersistent, Groups: []int64{staffID, modGroup.ID}})
	if err != nil {
		t.Fatal(err)
	}
	staffOnly, err := f.p.Create(f.Ctx, f.mod, NewChannel{Name: "staffroom", Kind: KindPersistent, Groups: []int64{staffID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Create(f.Ctx, f.mod, NewChannel{Name: "ghost", Kind: KindPersistent, Groups: []int64{99999}}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown group err = %v, want ErrInvalid", err)
	}
	adhoc, err := f.p.Create(f.Ctx, f.alice, NewChannel{Name: "mine", Kind: KindAdHoc, Groups: []int64{staffID}})
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := f.p.Get(f.Ctx, adhoc); c.Restricted || len(c.Groups) != 0 {
		t.Errorf("private chat kept groups: %+v (it is invite-only)", c)
	}

	tests := []struct {
		name    string
		user    int64
		channel int64
		want    bool
	}{
		{"member, not in any group", f.alice, both, false},
		{"in the first group", dave, both, true},
		{"in the second group", f.mod, both, true},
		{"administrator", f.Admin, both, true},
		{"in the only group", dave, staffOnly, true},
		{"moderator outside the group", f.mod, staffOnly, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := f.p.Get(f.Ctx, tt.channel)
			if got, err := f.p.CanAccess(f.Ctx, tt.user, c); got != tt.want || err != nil {
				t.Errorf("CanAccess = %v (err %v), want %v", got, err, tt.want)
			}
		})
	}

	// Deleting the only group must leave the channel closed, not open.
	if err := f.Perms.DeleteGroup(f.Ctx, f.Admin, staffID); err != nil {
		t.Fatal(err)
	}
	c, _ := f.p.Get(f.Ctx, staffOnly)
	if ok, _ := f.p.CanAccess(f.Ctx, f.alice, c); ok {
		t.Error("after its group was deleted, any member can join the channel")
	}
	if ok, _ := f.p.CanAccess(f.Ctx, f.Admin, c); !ok {
		t.Error("administrator lost access")
	}
}

// TestMigrationConvertsPermission checks that version 2 turns a version 1
// channel permission into the groups that held it, leaving private chats
// invite-only.
func TestMigrationConvertsPermission(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "m.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	migs := New().Manifest().Migrations
	if err := store.Migrate(ctx, db, "chat", migs[:1], log); err != nil {
		t.Fatal(err)
	}
	var modGroup int64
	if err := db.QueryRowContext(ctx, `SELECT id FROM access_groups WHERE name = ?`, perm.GroupModerator).Scan(&modGroup); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO access_group_permissions (group_id, permission) VALUES (` + strconv.FormatInt(modGroup, 10) + `, 'test.secret')`,
		`INSERT INTO chat_channels (name, kind, permission, created_at) VALUES ('secret', 'persistent', 'test.secret', '2026-01-01T00:00:00Z')`,
		`INSERT INTO chat_channels (name, kind, permission, created_at) VALUES ('dm', 'adhoc', 'test.secret', '2026-01-01T00:00:00Z')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Migrate(ctx, db, "chat", migs, log); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name           string
		wantRestricted bool
		wantGroups     string
	}{
		{"lobby", false, ""},
		{"secret", true, strconv.FormatInt(modGroup, 10)},
		{"dm", false, ""},
	}
	for _, tt := range tests {
		var restricted bool
		var groups string
		err := db.QueryRowContext(ctx, `SELECT c.restricted, COALESCE((SELECT group_concat(group_id) FROM chat_channel_groups WHERE channel_id = c.id), '')
			FROM chat_channels c WHERE c.name = ?`, tt.name).Scan(&restricted, &groups)
		if err != nil {
			t.Fatal(err)
		}
		if restricted != tt.wantRestricted || groups != tt.wantGroups {
			t.Errorf("%s: restricted=%v groups=%q, want %v %q", tt.name, restricted, groups, tt.wantRestricted, tt.wantGroups)
		}
	}
}

func TestFindAndAccessibleMatchCanAccess(t *testing.T) {
	f := setup(t)
	modG, _ := f.Perms.GroupByName(f.Ctx, perm.GroupModerator)
	if _, err := f.p.Create(f.Ctx, f.mod, NewChannel{Name: "gardening", Kind: KindPersistent, Topic: "Plants and seeds"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Create(f.Ctx, f.mod, NewChannel{Name: "staff-garden", Kind: KindPersistent, Groups: []int64{modG.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.createAdHoc(f.Ctx, f.alice, "plans", "Garden party", "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.createAdHoc(f.Ctx, f.carol, "secret", "", ""); err != nil {
		t.Fatal(err)
	}

	names := func(cs []Channel) string {
		var n []string
		for _, c := range cs {
			n = append(n, c.Name)
		}
		return strings.Join(n, ",")
	}
	tests := []struct {
		name  string
		user  int64
		query string
		want  string
		err   error
	}{
		{"name part", f.alice, "garden", "gardening,plans", nil}, // plans by its topic
		{"topic, any case", f.bob, "SEEDS", "gardening", nil},
		{"leading #", f.bob, "#lob", "lobby", nil},
		{"group channel for its group", f.mod, "staff", "staff-garden", nil},
		{"group channel hidden from others", f.alice, "staff", "", nil},
		{"private chat hidden from the uninvited", f.carol, "plans", "", nil},
		{"empty", f.alice, "  ", "", ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := f.p.FindAccessible(f.Ctx, tt.user, tt.query)
			if !errors.Is(err, tt.err) || names(got) != tt.want {
				t.Errorf("FindAccessible(%q) = %q, %v; want %q, %v", tt.query, names(got), err, tt.want, tt.err)
			}
		})
	}

	// The batched listing must agree with checking each channel alone.
	var all []Channel
	rows, _ := f.DB.Query(`SELECT id FROM chat_channels`)
	for rows.Next() {
		var id int64
		rows.Scan(&id)
		c, _ := f.p.Get(f.Ctx, id)
		all = append(all, c)
	}
	rows.Close()
	for _, u := range []int64{f.alice, f.bob, f.carol, f.mod, f.Admin} {
		listed, err := f.p.Accessible(f.Ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		in := map[int64]bool{}
		for _, c := range listed {
			in[c.ID] = true
		}
		for _, c := range all {
			if ok, _ := f.p.CanAccess(f.Ctx, u, c); ok != in[c.ID] {
				t.Errorf("user %d, #%s: listed %v, CanAccess %v", u, c.Name, in[c.ID], ok)
			}
		}
	}
}

func TestFindChannelTUI(t *testing.T) {
	f := setup(t)
	if _, err := f.p.Create(f.Ctx, f.mod, NewChannel{Name: "gardening", Kind: KindPersistent, Topic: "Plants"}); err != nil {
		t.Fatal(err)
	}
	// Chat menu (1 gardening, 2 lobby; f Find a channel, n Start a private
	// chat, a Page someone, q Back): Find, search "plant", pick the match (1), leave the
	// channel, back.
	s := f.Session(f.alice, strings.Join([]string{"f", "plant", "1", "/quit", "q"}, "\r")+"\r")
	if err := f.p.run(f.Ctx, s); err != nil {
		t.Fatalf("run: %v\n%s", err, s.Out)
	}
	out := s.Out.String()
	for _, want := range []string{"Actions: f Find a channel; n Start a private chat; a Page someone; q Back.", "Find a channel: 1 match(es)", "1. #gardening [C]", "#gardening, channel."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}
