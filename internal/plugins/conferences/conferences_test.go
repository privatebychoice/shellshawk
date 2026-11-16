package conferences

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/chat"
	"go.privatebychoice.com/shellshawk/internal/plugins/plugintest"
	"go.privatebychoice.com/shellshawk/internal/plugins/polls"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
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
	staff, err := p.CreateConference(e.Ctx, f.mod, areas[0].ID, "staff", "Staff room", "", perm.UsersApprove)
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
	if c, _ := f.chat.Get(f.Ctx, cid); c.Permission != perm.UsersApprove {
		t.Errorf("thread chat permission = %q, want the conference's", c.Permission)
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
