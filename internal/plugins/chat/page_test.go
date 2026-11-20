package chat

import (
	"context"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/privacy"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

func TestPage(t *testing.T) {
	f := setup(t)
	lobby, err := f.p.ByName(f.Ctx, "lobby")
	if err != nil {
		t.Fatal(err)
	}
	modGroup, _ := f.Perms.GroupByName(f.Ctx, perm.GroupModerator)
	staff, err := f.p.Create(f.Ctx, f.mod, NewChannel{Name: "staff", Kind: KindPersistent, Groups: []int64{modGroup.ID}})
	if err != nil {
		t.Fatal(err)
	}
	staffCh, _ := f.p.Get(f.Ctx, staff)
	alice, carol := f.user(t, f.alice), f.user(t, f.carol)

	// Each step changes the state the next one sees.
	steps := []struct {
		name  string
		setup func()
		from  int64
		to    string
		in    Channel
		want  error  // nil = paged
		msg   string // part of the error
	}{
		{"offline", nil, f.alice, "bob", lobby, ErrCannotPage, ""},
		{"online, but only friends may page", func() { f.Presence.Enter(f.bob) }, f.alice, "bob", lobby, ErrCannotPage, ""},
		// Paging is open to all, but bob shows that he is online only to
		// friends: a page must not reveal it, so it is refused exactly as
		// if he were offline.
		{"anyone may page, online hidden", func() { f.Visibility(f.bob, privacy.Pages, privacy.Public) }, f.alice, "bob", lobby, ErrCannotPage, ""},
		{"anyone may page", func() { f.Visibility(f.bob, privacy.Online, privacy.Public) }, f.alice, "@bob", lobby, nil, ""},
		{"again too soon", nil, f.alice, "bob", lobby, ErrInvalid, "you paged bob recently; you can page them again in 5 minute(s)"},
		{"yourself", nil, f.alice, "alice", lobby, ErrInvalid, "you cannot page yourself"},
		{"nobody", nil, f.alice, "nobody", lobby, ErrInvalid, `no active member called "nobody"`},
		{"to a channel they cannot join", nil, f.mod, "bob", staffCh, ErrInvalid, "#staff is not open to bob; page them from a private chat instead"},
		{"pages turned off", func() { f.Notify.SetSettings(f.Ctx, f.bob, map[string]bool{NotifyPage: false}) }, f.carol, "bob", lobby, ErrCannotPage, ""},
		{"without chat.page", func() {
			member, _ := f.Perms.GroupByName(f.Ctx, perm.GroupMember)
			if err := f.Perms.Revoke(f.Ctx, f.Admin, member.ID, PermPage); err != nil {
				t.Fatal(err)
			}
		}, f.alice, "mod1", lobby, perm.ErrForbidden, ""},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			if st.setup != nil {
				st.setup()
			}
			_, err := f.p.Page(f.Ctx, f.user(t, st.from), st.to, st.in)
			if (st.want == nil) != (err == nil) || (st.want != nil && !errors.Is(err, st.want)) || !strings.Contains(errString(err), st.msg) {
				t.Errorf("Page = %v, want %v containing %q", err, st.want, st.msg)
			}
		})
	}
	list, err := f.Notify.List(f.Ctx, f.bob)
	if err != nil || len(list) != 1 {
		t.Fatalf("bob's notifications = %+v, %v", list, err)
	}
	if n := list[0]; n.Kind != NotifyPage || n.Actor != "alice" || n.Text != "would like to talk in #lobby" || n.Ref != strconv.FormatInt(lobby.ID, 10) || n.Seen {
		t.Errorf("page notification = %+v", n)
	}

	// A private chat invites the member paged; the talk chat between two
	// members is found again from either side.
	member, _ := f.Perms.GroupByName(f.Ctx, perm.GroupMember)
	f.Perms.Grant(f.Ctx, f.Admin, member.ID, PermPage)
	f.Presence.Enter(f.carol)
	f.Visibility(f.carol, privacy.Pages, privacy.Public)
	f.Visibility(f.carol, privacy.Online, privacy.Public)
	talk, err := f.p.talkChat(f.Ctx, alice, carol)
	if err != nil || talk.Name != "talk-alice-carol" || talk.Kind != KindAdHoc {
		t.Fatalf("talk chat = %+v, %v", talk, err)
	}
	if ok, _ := f.p.CanAccess(f.Ctx, f.carol, talk); ok {
		t.Error("carol could join before being paged")
	}

	// carol is in #lobby: she sees the page there at once, so it is not new.
	m := f.p.hub.join(lobby.ID, f.carol, "carol")
	defer f.p.hub.leave(lobby.ID, m)
	if _, err := f.p.Page(f.Ctx, alice, "carol", talk); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.p.CanAccess(f.Ctx, f.carol, talk); !ok {
		t.Error("paging did not invite carol")
	}
	select {
	case l := <-m.out:
		if !strings.Contains(l.Plain(), "alice is paging you to talk in #talk-alice-carol. Type /join talk-alice-carol") {
			t.Errorf("live line = %q", l.Plain())
		}
	default:
		t.Error("no live line")
	}
	if n, _ := f.Notify.CountUnseen(f.Ctx, f.carol); n != 0 {
		t.Errorf("a page seen live is still new (%d)", n)
	}
	for _, pair := range [][2]int64{{f.alice, f.carol}, {f.carol, f.alice}} {
		again, err := f.p.talkChat(f.Ctx, f.user(t, pair[0]), f.user(t, pair[1]))
		if err != nil || again.ID != talk.ID {
			t.Errorf("talk chat %v = %d, %v; want %d", pair, again.ID, err, talk.ID)
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestPagerWait(t *testing.T) {
	var pg pager
	t0 := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	every := 5 * time.Minute
	tests := []struct {
		name     string
		from, to int64
		at       time.Duration
		want     time.Duration
	}{
		{"first page", 1, 2, 0, 0},
		{"same pair soon after", 1, 2, time.Minute, 4 * time.Minute},
		{"other direction", 2, 1, time.Minute, 0},
		{"other member", 1, 3, time.Minute, 0},
		{"same pair after the interval", 1, 2, every, 0},
	}
	for _, tt := range tests {
		if got := pg.wait(tt.from, tt.to, t0.Add(tt.at), every); got != tt.want {
			t.Errorf("%s: wait = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestTalkName(t *testing.T) {
	tests := []struct{ a, b, want string }{
		{"alice", "bob", "talk-alice-bob"},
		{"Ann_Lee", "x.y", "talk-ann-lee-x-y"},
		{"averyveryverylongname", "another", "talk-averyveryverylongname-an"},
		{"abcdefghijklmnopqrstuvw", "zz", "talk-abcdefghijklmnopqrstuvw"},
	}
	for _, tt := range tests {
		got := talkName(tt.a, tt.b)
		if got != tt.want || !namePattern.MatchString(got) {
			t.Errorf("talkName(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestPageTUI(t *testing.T) {
	f := setup(t)
	f.Presence.Enter(f.bob)
	f.Visibility(f.bob, privacy.Pages, privacy.Public)
	f.Visibility(f.bob, privacy.Online, privacy.Public)

	// Chat menu: a Page someone; "nobody" is refused on the form; bob is
	// paged; Enter dismisses the message; alice waits in the talk chat and
	// leaves; q.
	s := f.Session(f.alice, strings.Join([]string{"a", "nobody", "bob", "", "/quit", "q"}, "\r")+"\r")
	if err := f.p.run(f.Ctx, s); err != nil {
		t.Fatalf("run: %v\n%s", err, s.Out)
	}
	out := s.Out.String()
	for _, want := range []string{"a Page someone", `No member called "nobody"`, "bob has been paged. Wait for them in #talk-alice-bob.", "#talk-alice-bob, private chat."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n%s", want, out)
		}
	}

	// bob opens the notification: it takes him to the chat; /page from
	// inside works too.
	list, _ := f.Notify.List(f.Ctx, f.bob)
	if len(list) != 1 {
		t.Fatalf("bob's notifications = %+v", list)
	}
	k, ok := f.Registry.NotificationKind(NotifyPage)
	if !ok || k.Open == nil || k.OpenLabel != "Go to the chat" || k.WebPath == nil {
		t.Fatalf("page kind = %+v, %v", k, ok)
	}
	if talk, _ := f.p.ByName(f.Ctx, "talk-alice-bob"); k.WebPath(list[0]) != "/c/"+strconv.FormatInt(talk.ID, 10) {
		t.Errorf("web path = %q", k.WebPath(list[0]))
	}
	f.Presence.Enter(f.alice)
	f.Visibility(f.alice, privacy.Pages, privacy.Public)
	f.Visibility(f.alice, privacy.Online, privacy.Public)
	bs := f.Session(f.bob, "/page alice\r/page alice\r/quit\r")
	if err := k.Open(f.Ctx, bs, list[0]); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#talk-alice-bob, private chat.", "alice has been paged to #talk-alice-bob.", "You paged alice recently"} {
		if !strings.Contains(bs.Out.String(), want) {
			t.Errorf("bob's output missing %q\n%s", want, bs.Out.String())
		}
	}

	// Once the chat is gone the notification says so.
	talk, _ := f.p.ByName(f.Ctx, "talk-alice-bob")
	if err := f.p.Destroy(f.Ctx, f.alice, talk.ID); err != nil {
		t.Fatal(err)
	}
	gone := f.Session(f.bob, "\r")
	if err := k.Open(f.Ctx, gone, list[0]); err != nil && !errors.Is(err, tui.ErrCancelled) {
		t.Fatal(err)
	}
	if !strings.Contains(gone.Out.String(), "That chat no longer exists, or you can no longer join it.") {
		t.Errorf("closed chat:\n%s", gone.Out.String())
	}
}

func TestWebPaging(t *testing.T) {
	f := setup(t)
	lobby, _ := f.p.ByName(f.Ctx, "lobby")
	lobbyID := map[string]string{"id": strconv.FormatInt(lobby.ID, 10)}
	f.Visibility(f.bob, privacy.Pages, privacy.Public)
	f.Visibility(f.bob, privacy.Online, privacy.Public)
	f.Visibility(f.carol, privacy.Pages, privacy.Public)
	f.Visibility(f.carol, privacy.Online, privacy.Public)

	// The chat list offers paging; the form asks for a username.
	if list, _ := f.WebGet(f.p, "/", nil, f.alice); !strings.Contains(string(list.Body), `href="/p/chat/page">Page someone`) {
		t.Errorf("list without the paging link:\n%s", list.Body)
	}
	if form, err := f.WebGet(f.p, "/page", nil, f.alice); err != nil || !strings.Contains(string(form.Body), `<label for="page-user">Username</label>`) {
		t.Errorf("page form = %s, %v", form.Body, err)
	}

	// bob is only on the web, following #lobby: that counts as online.
	ctx, cancel := context.WithCancel(f.Ctx)
	bobStream := f.stream(t, ctx, f.bob, lobby.ID)

	tests := []struct {
		name, path string
		values     map[string]string
		user       string
		want       string // in the re-shown form; "" = paged
	}{
		{"nobody", "/page", nil, "nobody", `No member called &#34;nobody&#34;.`},
		{"offline", "/page", nil, "carol", "carol cannot be paged right now."},
		{"yourself", "/page", nil, "alice", "You cannot page yourself."},
		{"on the web", "/page", nil, "@bob", ""},
		{"again too soon", "/page", nil, "bob", "You paged bob recently; you can page them again in 5 minute(s)."},
		{"offline, from a channel", "/c/{id}/page", lobbyID, "carol", "carol cannot be paged right now."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := f.WebPost(f.p, tt.path, tt.values, url.Values{"username": {tt.user}}, f.alice)
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if !strings.HasPrefix(page.Redirect, "/p/chat/c/") || !strings.Contains(page.Redirect, "?done=paged") {
					t.Errorf("redirect = %q\n%s", page.Redirect, page.Body)
				}
				return
			}
			if b := string(page.Body); !strings.Contains(b, tt.want) || !strings.Contains(b, `aria-invalid="true"`) {
				t.Errorf("want %q in:\n%s", tt.want, b)
			}
		})
	}
	cancel()
	if got := <-bobStream; !strings.Contains(got, "alice is paging you to talk in #talk-alice-bob. Open it from Notifications or the chat list.") || strings.Contains(got, "/join") {
		t.Errorf("bob's web stream:\n%s", got)
	}
	if n, _ := f.Notify.CountUnseen(f.Ctx, f.bob); n != 0 {
		t.Errorf("a page seen live on the web is still new (%d)", n)
	}

	// From a channel page: the form is there, and carol, now online, is
	// paged to #lobby.
	if page, _ := f.WebGet(f.p, "/c/{id}", lobbyID, f.alice); !strings.Contains(string(page.Body), `<h2 id="page-heading">Page a member</h2>`) {
		t.Errorf("channel page without the paging form:\n%s", page.Body)
	}
	f.Presence.Enter(f.carol)
	page, err := f.WebPost(f.p, "/c/{id}/page", lobbyID, url.Values{"username": {"carol"}}, f.alice)
	if err != nil || page.Redirect != "/p/chat/c/"+lobbyID["id"]+"?done=paged#page-heading" {
		t.Errorf("page carol = %+v, %v", page, err)
	}
	if list, _ := f.Notify.List(f.Ctx, f.carol); len(list) != 1 || list[0].Text != "would like to talk in #lobby" {
		t.Errorf("carol's notifications = %+v", list)
	}

	// Without chat.page the form is not shown.
	member, _ := f.Perms.GroupByName(f.Ctx, perm.GroupMember)
	if err := f.Perms.Revoke(f.Ctx, f.Admin, member.ID, PermPage); err != nil {
		t.Fatal(err)
	}
	if page, _ := f.WebGet(f.p, "/c/{id}", lobbyID, f.alice); strings.Contains(string(page.Body), "Page a member") {
		t.Error("paging form shown without chat.page")
	}
	if list, _ := f.WebGet(f.p, "/", nil, f.alice); strings.Contains(string(list.Body), "Page someone") {
		t.Error("paging link shown without chat.page")
	}
}
