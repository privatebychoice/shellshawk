package conferences

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/chat"
	"go.privatebychoice.com/shellshawk/internal/plugins/plugintest"
	"go.privatebychoice.com/shellshawk/internal/plugins/polls"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
	"go.privatebychoice.com/shellshawk/internal/store"
)

type fixture struct {
	*plugintest.Env
	p                 *Plugin
	polls             *polls.Plugin
	chat              *chat.Plugin
	alice, bob, mod   int64
	general, staffCnf int64
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pl, ch := polls.New(), chat.New()
	p := New(pl, ch)
	e := plugintest.New(t, pl, ch, p)
	f := &fixture{Env: e, p: p, polls: pl, chat: ch, alice: e.User("alice"), bob: e.User("bob"), mod: e.User("mod1", perm.GroupModerator)}
	areas, _ := p.Areas(e.Ctx)
	confs, _ := p.Conferences(e.Ctx, f.alice, areas[0].ID)
	if len(confs) != 1 || confs[0].Slug != "general" {
		t.Fatalf("seeded conferences = %+v", confs)
	}
	f.general = confs[0].ID
	modGroup, err := e.Perms.GroupByName(e.Ctx, perm.GroupModerator)
	if err != nil {
		t.Fatal(err)
	}
	staff, err := p.CreateConference(e.Ctx, f.mod, areas[0].ID, "staff", "Staff room", "", []int64{modGroup.ID})
	if err != nil {
		t.Fatal(err)
	}
	f.staffCnf = staff
	return f
}

func TestAccessAndPosting(t *testing.T) {
	f := setup(t)
	areas, _ := f.p.Areas(f.Ctx)
	if cs, _ := f.p.Conferences(f.Ctx, f.alice, areas[0].ID); len(cs) != 1 {
		t.Errorf("member sees %d conferences, want 1 (staff is restricted)", len(cs))
	}
	if cs, _ := f.p.Conferences(f.Ctx, f.mod, areas[0].ID); len(cs) != 2 {
		t.Errorf("moderator sees %d conferences, want 2", len(cs))
	}
	if _, _, err := f.p.StartThread(f.Ctx, f.alice, f.staffCnf, "x", "y"); !errors.Is(err, ErrNotFound) {
		t.Errorf("posting in a restricted conference err = %v (must look absent)", err)
	}
	if _, err := f.p.CreateArea(f.Ctx, f.alice, "news", "News", ""); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member creating an area err = %v", err)
	}

	tests := []struct {
		name, title, body string
		want              error
	}{
		{"ok", "Hello world", "First **post**", nil},
		{"empty title", "  ", "x", ErrInvalid},
		{"escape in title", "Hi\x1b[2J", "x", ErrInvalid},
		{"empty body", "Hi", "\n", ErrInvalid},
		{"control in body", "Hi", "x\x1b]0;t\x07", ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := f.p.StartThread(f.Ctx, f.alice, f.general, tt.title, tt.body); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestThreadLifecycle(t *testing.T) {
	f := setup(t)
	tid, first, err := f.p.StartThread(f.Ctx, f.alice, f.general, "Plans", "Saturday?")
	if err != nil {
		t.Fatal(err)
	}
	reply, err := f.p.Reply(f.Ctx, f.bob, tid, "Works for me")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.Edit(f.Ctx, f.alice, reply, "hijack"); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("editing someone else's post err = %v", err)
	}
	if err := f.p.Edit(f.Ctx, f.bob, reply, "Works for me, see you"); err != nil {
		t.Fatal(err)
	}
	posts, _ := f.p.Posts(f.Ctx, f.alice, tid)
	if len(posts) != 2 || posts[1].EditedAt == nil || posts[1].Author != "bob" {
		t.Fatalf("posts = %+v", posts)
	}

	// Lock: no replies, authors can no longer edit; moderators still can.
	if err := f.p.SetLocked(f.Ctx, f.alice, tid, true); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member locking err = %v", err)
	}
	f.p.SetLocked(f.Ctx, f.mod, tid, true)
	if _, err := f.p.Reply(f.Ctx, f.bob, tid, "late"); !errors.Is(err, ErrLocked) {
		t.Errorf("reply to locked thread err = %v", err)
	}
	if err := f.p.Edit(f.Ctx, f.bob, reply, "x"); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("author editing in a locked thread err = %v", err)
	}
	f.p.SetLocked(f.Ctx, f.mod, tid, false)

	// A poll on the reply, then delete the reply: the poll goes too.
	pollID, err := f.polls.Create(f.Ctx, polls.Spec{Question: "Time?", Options: []string{"10", "11"}, CreatorID: f.bob, Context: pollContext(reply)})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.p.canAddPoll(f.Ctx, f.alice, reply); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("adding a poll to someone else's post err = %v", err)
	}
	if posts, _ := f.p.Posts(f.Ctx, f.alice, tid); len(posts[1].Polls) != 1 {
		t.Error("poll not attached to the post")
	}
	if gone, err := f.p.DeletePost(f.Ctx, f.bob, reply); err != nil || gone {
		t.Fatalf("delete reply = %v, %v", gone, err)
	}
	if _, err := f.polls.Get(f.Ctx, f.bob, pollID); !errors.Is(err, polls.ErrNotFound) {
		t.Errorf("poll survived its post: %v", err)
	}

	// Thread chat, then deleting the first post deletes thread and chat.
	if _, err := f.p.EnableChat(f.Ctx, f.alice, tid); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member enabling chat err = %v", err)
	}
	cid, err := f.p.EnableChat(f.Ctx, f.mod, tid)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := f.p.EnableChat(f.Ctx, f.mod, tid); again != cid {
		t.Error("enabling chat twice created a second channel")
	}
	if gone, err := f.p.DeletePost(f.Ctx, f.alice, first); err != nil || !gone {
		t.Fatalf("delete first post = %v, %v", gone, err)
	}
	if _, _, _, err := f.p.Thread(f.Ctx, f.alice, tid); !errors.Is(err, ErrNotFound) {
		t.Errorf("thread survived: %v", err)
	}
	if _, err := f.chat.Get(f.Ctx, cid); !errors.Is(err, chat.ErrNotFound) {
		t.Errorf("thread chat survived: %v", err)
	}
}

func TestDeleteConferenceCleansUp(t *testing.T) {
	f := setup(t)
	tid, post, _ := f.p.StartThread(f.Ctx, f.mod, f.staffCnf, "Secret", "x")
	pollID, _ := f.polls.Create(f.Ctx, polls.Spec{Question: "Q?", Options: []string{"a", "b"}, CreatorID: f.mod, Context: pollContext(post)})
	cid, _ := f.p.EnableChat(f.Ctx, f.mod, tid)
	c, _ := f.chat.Get(f.Ctx, cid)
	if ok, err := f.chat.CanAccess(f.Ctx, f.alice, c); ok || err != nil {
		t.Errorf("member outside the conference's groups can enter its thread chat (err %v)", err)
	}
	if ok, err := f.chat.CanAccess(f.Ctx, f.mod, c); !ok || err != nil {
		t.Errorf("group member cannot enter the thread chat (err %v)", err)
	}
	if err := f.p.DeleteConference(f.Ctx, f.alice, f.staffCnf); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member delete err = %v", err)
	}
	if err := f.p.DeleteConference(f.Ctx, f.mod, f.staffCnf); err != nil {
		t.Fatal(err)
	}
	if _, err := f.polls.Get(f.Ctx, f.mod, pollID); !errors.Is(err, polls.ErrNotFound) {
		t.Error("poll survived")
	}
	if _, err := f.chat.Get(f.Ctx, cid); !errors.Is(err, chat.ErrNotFound) {
		t.Error("chat survived")
	}
	areas, _ := f.p.Areas(f.Ctx)
	if err := f.p.DeleteArea(f.Ctx, f.mod, areas[0].ID); !errors.Is(err, ErrNotEmpty) {
		t.Errorf("deleting a non-empty area err = %v", err)
	}
}

func TestSFTP(t *testing.T) {
	f := setup(t)
	tid, _, _ := f.p.StartThread(f.Ctx, f.alice, f.general, "Hello, World!", "First post")
	f.p.Reply(f.Ctx, f.bob, tid, "Hi *alice*")
	f.p.StartThread(f.Ctx, f.mod, f.staffCnf, "Staff only", "secret")
	fs := &threadFS{p: f.p}
	alice := sftpd.User{ID: f.alice, Name: "alice"}

	confs, _ := fs.List(f.Ctx, alice, []string{"general"})
	if len(confs) != 1 || confs[0].Name != "general" {
		t.Errorf("alice sees conferences %+v (staff must be hidden)", confs)
	}
	files, err := fs.List(f.Ctx, alice, []string{"general", "general"})
	if err != nil || len(files) != 1 || !strings.HasSuffix(files[0].Name, "-hello-world.md") {
		t.Fatalf("files = %+v, %v", files, err)
	}
	data, _, err := fs.Read(f.Ctx, alice, []string{"general", "general", files[0].Name})
	if err != nil || !strings.Contains(string(data), "First post") || !strings.Contains(string(data), "Hi *alice*") || !strings.Contains(string(data), "posts: 2") {
		t.Errorf("thread file = %q, %v", data, err)
	}
	if _, err := fs.List(f.Ctx, alice, []string{"general", "staff"}); !errors.Is(err, sftpd.ErrNotExist) {
		t.Errorf("listing a restricted conference err = %v", err)
	}
	// The right thread ID under the wrong conference is not found.
	mod := sftpd.User{ID: f.mod, Name: "mod1"}
	if _, _, err := fs.Read(f.Ctx, mod, []string{"general", "staff", files[0].Name}); !errors.Is(err, sftpd.ErrNotExist) {
		t.Errorf("thread read via another conference err = %v", err)
	}
}

func TestWebPages(t *testing.T) {
	f := setup(t)
	tid, _, _ := f.p.StartThread(f.Ctx, f.alice, f.general, "Hello <web>", "**bold** <script>alert(1)</script>")
	staffThread, _, _ := f.p.StartThread(f.Ctx, f.mod, f.staffCnf, "Staff", "x")
	id := func(n int64) map[string]string { return map[string]string{"id": strconv.FormatInt(n, 10)} }

	areas, err := f.WebGet(f.p, "/", nil, f.alice)
	if err != nil || !strings.Contains(string(areas.Body), "General discussion") || strings.Contains(string(areas.Body), "Staff room") {
		t.Errorf("areas page = %s, %v", areas.Body, err)
	}
	page, err := f.WebGet(f.p, "/t/{id}", id(tid), f.alice)
	if err != nil || page.Title != "Hello <web>" || !strings.Contains(string(page.Body), "<strong>bold</strong>") || strings.Contains(string(page.Body), "<script>") {
		t.Errorf("thread page = %q / %s, %v", page.Title, page.Body, err)
	}
	if _, err := f.WebGet(f.p, "/t/{id}", id(staffThread), f.alice); !errors.Is(err, plugin.ErrWebNotFound) {
		t.Errorf("restricted thread err = %v", err)
	}
	if _, err := f.WebGet(f.p, "/c/{id}", map[string]string{"id": "x"}, f.alice); !errors.Is(err, plugin.ErrWebNotFound) {
		t.Errorf("bad id err = %v", err)
	}
}

func TestCreateArea(t *testing.T) {
	f := setup(t)
	tests := []struct {
		name, slug, title string
		want              error
	}{
		{"ok", "news", "News", nil},
		{"second", "help", "Help desk", nil},
		{"duplicate", "news", "News again", ErrExists},
		{"bad short name", "No Spaces", "x", ErrInvalid},
		{"empty name", "empty", " ", ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := f.p.CreateArea(f.Ctx, f.mod, tt.slug, tt.title, "")
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			if err == nil && id == 0 {
				t.Error("no id returned")
			}
		})
	}
	areas, err := f.p.Areas(f.Ctx)
	if err != nil {
		t.Fatal(err)
	}
	var slugs []string
	for _, a := range areas {
		slugs = append(slugs, a.Slug)
	}
	if got := strings.Join(slugs[1:], ","); len(areas) != 3 || got != "news,help" {
		t.Errorf("areas after the seeded one = %q (%d total), want news,help in creation order", got, len(areas))
	}
}

func TestGroupAccess(t *testing.T) {
	f := setup(t)
	staffID, err := f.Perms.CreateGroup(f.Ctx, f.Admin, "staff", "Staff")
	if err != nil {
		t.Fatal(err)
	}
	modGroup, _ := f.Perms.GroupByName(f.Ctx, perm.GroupModerator)
	carol := f.User("carol", perm.GroupMember, "staff")
	areas, _ := f.p.Areas(f.Ctx)
	both, err := f.p.CreateConference(f.Ctx, f.mod, areas[0].ID, "ops", "Ops", "", []int64{staffID, modGroup.ID})
	if err != nil {
		t.Fatal(err)
	}
	staffOnly, err := f.p.CreateConference(f.Ctx, f.mod, areas[0].ID, "staffonly", "Staff only", "", []int64{staffID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.CreateConference(f.Ctx, f.mod, areas[0].ID, "ghost", "Ghost", "", []int64{99999}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown group err = %v, want ErrInvalid", err)
	}

	tests := []struct {
		name       string
		user       int64
		conf       int64
		wantAccess bool
	}{
		{"member, not in any group", f.alice, both, false},
		{"in the first group", carol, both, true},
		{"in the second group", f.mod, both, true},
		{"administrator", f.Admin, both, true},
		{"in the only group", carol, staffOnly, true},
		{"moderator outside the group", f.mod, staffOnly, false},
		{"open conference", f.alice, f.general, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := f.p.access(f.Ctx, tt.user, tt.conf)
			if got := err == nil; got != tt.wantAccess {
				t.Errorf("access = %v (err %v), want %v", got, err, tt.wantAccess)
			}
			if !tt.wantAccess && !errors.Is(err, ErrNotFound) {
				t.Errorf("err = %v, want ErrNotFound so the conference looks absent", err)
			}
		})
	}
	if _, _, err := f.p.StartThread(f.Ctx, carol, both, "Hi", "x"); err != nil {
		t.Errorf("group member cannot post: %v", err)
	}

	// Deleting the only group must leave the conference closed, not open.
	if err := f.Perms.DeleteGroup(f.Ctx, f.Admin, staffID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.p.access(f.Ctx, f.alice, staffOnly); !errors.Is(err, ErrNotFound) {
		t.Errorf("after its group was deleted, a member can open the conference (err %v)", err)
	}
	if _, _, err := f.p.access(f.Ctx, f.Admin, staffOnly); err != nil {
		t.Errorf("administrator lost access: %v", err)
	}
}

// TestMigrationConvertsPermission checks that version 2 turns a version 1
// per-conference permission into the groups that held it.
func TestMigrationConvertsPermission(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "m.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	migs := New(nil, nil).Manifest().Migrations
	if err := store.Migrate(ctx, db, "conferences", migs[:1], log); err != nil {
		t.Fatal(err)
	}
	var modGroup int64
	if err := db.QueryRowContext(ctx, `SELECT id FROM access_groups WHERE name = ?`, perm.GroupModerator).Scan(&modGroup); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO access_group_permissions (group_id, permission) VALUES (` + strconv.FormatInt(modGroup, 10) + `, 'test.secret')`,
		`INSERT INTO conferences_conferences (area_id, slug, name, permission, position, created_at)
			SELECT id, 'secret', 'Secret', 'test.secret', 2, created_at FROM conferences_areas`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Migrate(ctx, db, "conferences", migs, log); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		slug           string
		wantRestricted bool
		wantGroups     string
	}{
		{"general", false, ""},
		{"secret", true, strconv.FormatInt(modGroup, 10)},
	}
	for _, tt := range tests {
		var restricted bool
		var groups string
		err := db.QueryRowContext(ctx, `SELECT c.restricted, COALESCE((SELECT group_concat(group_id) FROM conferences_conference_groups WHERE conference_id = c.id), '')
			FROM conferences_conferences c WHERE c.slug = ?`, tt.slug).Scan(&restricted, &groups)
		if err != nil {
			t.Fatal(err)
		}
		if restricted != tt.wantRestricted || groups != tt.wantGroups {
			t.Errorf("%s: restricted=%v groups=%q, want %v %q", tt.slug, restricted, groups, tt.wantRestricted, tt.wantGroups)
		}
	}
}

func TestChatNames(t *testing.T) {
	tests := []struct {
		name, conf, title string
		thread            int64
		want              []string
	}{
		{"words", "general", "Hello, World!", 7, []string{"general-hello-world", "general-hello-world-7", "thread-7"}},
		{"long title stops at a word", "general", "Planning the spring meetup in the park", 12,
			[]string{"general-planning-the-spring", "general-planning-the-spring-12", "thread-12"}},
		{"no usable words", "news", "¿¡!", 3, []string{"news", "news-3", "thread-3"}},
		{"slug starting with a digit", "2026-plans", "Budget", 4, []string{"c2026-plans-budget", "c2026-plans-budget-4", "thread-4"}},
		{"very long slug", strings.Repeat("a", 32), "x", 5, []string{strings.Repeat("a", 32), strings.Repeat("a", 30) + "-5", "thread-5"}},
	}
	valid := regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`) // chat's name rule
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := chatNames(tt.conf, tt.title, tt.thread)
			if strings.Join(got, " ") != strings.Join(tt.want, " ") {
				t.Errorf("chatNames = %v, want %v", got, tt.want)
			}
			for _, n := range got {
				if !valid.MatchString(n) {
					t.Errorf("%q is not a valid chat name", n)
				}
			}
		})
	}
}

func TestThreadChatNamesAndClosing(t *testing.T) {
	f := setup(t)
	tid, _, _ := f.p.StartThread(f.Ctx, f.alice, f.general, "Hello world", "x")
	tid2, _, _ := f.p.StartThread(f.Ctx, f.alice, f.general, "Hello world", "same title")
	cid, err := f.p.EnableChat(f.Ctx, f.mod, tid)
	if err != nil {
		t.Fatal(err)
	}
	cid2, err := f.p.EnableChat(f.Ctx, f.mod, tid2)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := f.chat.Get(f.Ctx, cid)
	c2, _ := f.chat.Get(f.Ctx, cid2)
	if c.Name != "general-hello-world" || c2.Name != "general-hello-world-"+strconv.FormatInt(tid2, 10) {
		t.Errorf("chat names = %q, %q", c.Name, c2.Name)
	}

	// A moderator closes the chat from the Chat menu: the thread must
	// forget it rather than fail to open it.
	if err := f.chat.Destroy(f.Ctx, f.mod, cid); err != nil {
		t.Fatal(err)
	}
	th, _, _, err := f.p.Thread(f.Ctx, f.alice, tid)
	if err != nil || th.ChatChannelID != 0 {
		t.Fatalf("after closing, thread chat = %d, err %v; want none", th.ChatChannelID, err)
	}
	var stored any
	f.DB.QueryRow(`SELECT chat_channel_id FROM conferences_threads WHERE id = ?`, tid).Scan(&stored)
	if stored != nil {
		t.Errorf("stored chat_channel_id = %v, want NULL", stored)
	}
	again, err := f.p.EnableChat(f.Ctx, f.mod, tid)
	if err != nil || again == cid {
		t.Errorf("re-enabling: id %d (old %d), err %v", again, cid, err)
	}
}

func TestWebThreadChatPanel(t *testing.T) {
	f := setup(t)
	tid, _, _ := f.p.StartThread(f.Ctx, f.alice, f.general, "Chatty", "x")
	staffThread, _, _ := f.p.StartThread(f.Ctx, f.mod, f.staffCnf, "Staff", "x")
	id := func(n int64) map[string]string { return map[string]string{"id": strconv.FormatInt(n, 10)} }

	page, err := f.WebGet(f.p, "/t/{id}", id(tid), f.alice)
	if err != nil || strings.Contains(string(page.Body), "data-live-events") {
		t.Errorf("thread without chat shows a chat panel (err %v)", err)
	}
	if _, err := f.p.EnableChat(f.Ctx, f.mod, tid); err != nil {
		t.Fatal(err)
	}
	page, err = f.WebGet(f.p, "/t/{id}", id(tid), f.alice)
	if err != nil {
		t.Fatal(err)
	}
	body := string(page.Body)
	for _, want := range []string{"data-live-events=\"/p/chat/c/", "Thread chat", `name="csrf" value="test-csrf"`,
		`name="return" value="/p/conferences/t/` + strconv.FormatInt(tid, 10) + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("thread page missing %q", want)
		}
	}

	// The chat of a group-only thread follows the conference's groups.
	scid, err := f.p.EnableChat(f.Ctx, f.mod, staffThread)
	if err != nil {
		t.Fatal(err)
	}
	if html, err := f.chat.WebPanel(f.Ctx, f.alice, scid, "Thread chat", "t", "/"); err != nil || html != "" {
		t.Errorf("member outside the groups gets the staff chat panel (err %v)", err)
	}
}
