package chat

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
)

func (f *fixture) chanID(id int64) map[string]string {
	return map[string]string{"id": strconv.FormatInt(id, 10)}
}

func TestWebListAndFind(t *testing.T) {
	f := setup(t)
	priv, err := f.p.createAdHoc(f.Ctx, f.alice, "plans", "Weekend plans", "bob")
	if err != nil {
		t.Fatal(err)
	}
	modGroup, _ := f.Perms.GroupByName(f.Ctx, perm.GroupModerator)
	if _, err := f.p.Create(f.Ctx, f.mod, NewChannel{Name: "staff", Kind: KindPersistent, Groups: []int64{modGroup.ID}, RetentionDays: 1}); err != nil {
		t.Fatal(err)
	}

	list, err := f.WebGet(f.p, "/", nil, f.alice)
	b := string(list.Body)
	if err != nil || !strings.Contains(b, `<h2 id="channels">Channels</h2>`) || !strings.Contains(b, `<h2 id="private">Private chats</h2>`) ||
		!strings.Contains(b, `href="/p/chat/c/`+strconv.FormatInt(priv, 10)+`">#plans</a> <span class="meta">nobody here · Weekend plans`) ||
		!strings.Contains(b, `href="/p/chat/new">Start a private chat`) || strings.Contains(b, "#staff") || strings.Contains(b, "thread chats") {
		t.Errorf("alice's list = %s, %v", b, err)
	}
	if list, _ := f.WebGet(f.p, "/", nil, f.carol); strings.Contains(string(list.Body), "#plans") {
		t.Error("carol sees a private chat she was not invited to")
	}

	tests := []struct {
		name, q   string
		user      int64
		want, not string
	}{
		{"finds the private chat", "plan", f.alice, "#plans", "#lobby"},
		{"by topic, case and # ignored", "#WEEKEND", f.bob, "#plans", "No channel"},
		{"not someone else's private chat", "plan", f.carol, "No channel you can join matches \u201cplan\u201d.", "#plans"},
		{"not a restricted channel", "staff", f.alice, "No channel you can join matches", "#staff"},
		{"empty search", " ", f.alice, "Type a channel name, or part of one.", "#"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := f.WebGetQuery(f.p, "/find", nil, url.Values{"q": {tt.q}}, tt.user)
			if b := string(page.Body); err != nil || !strings.Contains(b, tt.want) || strings.Contains(b, tt.not) || !strings.Contains(b, "All chats") {
				t.Errorf("find %q = %s, %v", tt.q, b, err)
			}
		})
	}

	// Without chat.create: no link, and the form routes need it.
	member, _ := f.Perms.GroupByName(f.Ctx, perm.GroupMember)
	if err := f.Perms.Revoke(f.Ctx, f.Admin, member.ID, PermCreate); err != nil {
		t.Fatal(err)
	}
	if list, _ := f.WebGet(f.p, "/", nil, f.bob); strings.Contains(string(list.Body), "Start a private chat") {
		t.Error("start link shown without chat.create")
	}
	for _, r := range f.p.Manifest().Web {
		if r.Path == "/new" && !slices.Equal(r.AnyOf, []string{PermCreate}) {
			t.Errorf("%s %s needs %v, want chat.create", r.Method, r.Path, r.AnyOf)
		}
	}
}

func TestWebChannelPage(t *testing.T) {
	f := setup(t)
	lobby, _ := f.p.ByName(f.Ctx, "lobby")
	priv, _ := f.p.createAdHoc(f.Ctx, f.alice, "plans", "", "bob")
	tests := []struct {
		name      string
		ch, user  int64
		want, not []string
		notFound  bool
	}{
		{"creator: every form", priv, f.alice, []string{
			"<h2 id=\"chat-heading\">Messages</h2>", "Started by alice. Invited: bob.", `action="/p/chat/c/` + strconv.FormatInt(priv, 10) + `/invite"`,
			"Change the topic", `<option value="bob">bob</option>`, "Close this chat", `type="checkbox" name="confirm" value="yes" required`,
		}, nil, false},
		{"invited member: invite only", priv, f.bob, []string{"Invite a member"}, []string{"Change the topic", "Remove a member", "Close this chat"}, false},
		{"chat moderator may manage", priv, f.mod, []string{"Change the topic", "Close this chat"}, nil, false},
		{"not invited", priv, f.carol, nil, nil, true},
		{"public channel: no private chat forms", lobby.ID, f.alice, []string{"#lobby, channel."}, []string{"Private chat", "Invite a member"}, false},
		{"unknown channel", 9999, f.alice, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := f.WebGet(f.p, "/c/{id}", f.chanID(tt.ch), tt.user)
			if tt.notFound {
				if !errors.Is(err, plugin.ErrWebNotFound) {
					t.Errorf("err = %v, want not found", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tt.want {
				if !strings.Contains(string(page.Body), w) {
					t.Errorf("missing %q in:\n%s", w, page.Body)
				}
			}
			for _, w := range tt.not {
				if strings.Contains(string(page.Body), w) {
					t.Errorf("unexpected %q in:\n%s", w, page.Body)
				}
			}
		})
	}
	// The creator cannot remove themselves: they are not offered.
	page, _ := f.WebGet(f.p, "/c/{id}", f.chanID(priv), f.alice)
	if strings.Contains(string(page.Body), `<option value="alice">`) {
		t.Error("creator offered for removal")
	}
}

func TestWebPrivateActions(t *testing.T) {
	f := setup(t)
	lobby, _ := f.p.ByName(f.Ctx, "lobby")
	priv, _ := f.p.createAdHoc(f.Ctx, f.alice, "plans", "", "bob")
	base := "/p/chat/c/" + strconv.FormatInt(priv, 10)
	tests := []struct {
		name, path string
		ch, user   int64
		form       url.Values
		redirect   string // on success
		formError  string // the form shown again with this error
		notFound   bool
	}{
		{"invite", "/c/{id}/invite", priv, f.bob, url.Values{"username": {"@carol"}}, base + "?done=invite#private-heading", "", false},
		{"invite unknown", "/c/{id}/invite", priv, f.bob, url.Values{"username": {"ghost"}}, "", "No member called &#34;ghost&#34;.", false},
		{"topic needs the creator", "/c/{id}/topic", priv, f.bob, url.Values{"topic": {"Mine"}}, "", "", false},
		{"topic", "/c/{id}/topic", priv, f.alice, url.Values{"topic": {"Pizza"}}, base + "?done=topic#private-heading", "", false},
		{"topic with escapes", "/c/{id}/topic", priv, f.alice, url.Values{"topic": {"a\x1b[2J"}}, "", "Topics are at most", false},
		{"remove yourself", "/c/{id}/remove", priv, f.alice, url.Values{"username": {"alice"}}, "", "You cannot remove yourself", false},
		{"remove", "/c/{id}/remove", priv, f.alice, url.Values{"username": {"carol"}}, base + "?done=remove#private-heading", "", false},
		{"removed member can no longer act", "/c/{id}/invite", priv, f.carol, url.Values{"username": {"bob"}}, "", "", true},
		{"close needs the box ticked", "/c/{id}/close", priv, f.alice, url.Values{}, "", "Tick the box to confirm.", false},
		{"invite on a public channel", "/c/{id}/invite", lobby.ID, f.alice, url.Values{"username": {"bob"}}, "", "", true},
		{"close a public channel", "/c/{id}/close", lobby.ID, f.mod, url.Values{"confirm": {"yes"}}, "", "", true},
		{"close", "/c/{id}/close", priv, f.alice, url.Values{"confirm": {"yes"}}, "/p/chat/?done=closed", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := f.WebPost(f.p, tt.path, f.chanID(tt.ch), tt.form, tt.user)
			var we *plugin.WebError
			switch {
			case tt.redirect == "" && tt.formError == "" && !tt.notFound:
				if !errors.As(err, &we) || we.Status != http.StatusForbidden {
					t.Errorf("err = %v, want 403", err)
				}
			case tt.notFound:
				if !errors.Is(err, plugin.ErrWebNotFound) {
					t.Errorf("err = %v, want not found", err)
				}
			case tt.formError != "":
				if err != nil || page.Redirect != "" || !strings.Contains(string(page.Body), tt.formError) || !strings.Contains(string(page.Body), `role="alert"`) {
					t.Errorf("form error = %q, %v:\n%s", page.Redirect, err, page.Body)
				}
			default:
				if err != nil || page.Redirect != tt.redirect {
					t.Errorf("result = %q, %v; want redirect %q", page.Redirect, err, tt.redirect)
				}
			}
		})
	}
	if _, err := f.p.Get(f.Ctx, priv); !errors.Is(err, ErrNotFound) {
		t.Errorf("closed chat still exists: %v", err)
	}
}

func TestWebPrivateActionEffects(t *testing.T) {
	f := setup(t)
	priv, _ := f.p.createAdHoc(f.Ctx, f.alice, "plans", "", "bob")
	c, _ := f.p.Get(f.Ctx, priv)
	post := func(path string, form url.Values, user int64) plugin.WebPage {
		t.Helper()
		page, err := f.WebPost(f.p, path, f.chanID(priv), form, user)
		if err != nil {
			t.Fatal(err)
		}
		return page
	}

	post("/c/{id}/invite", url.Values{"username": {"carol"}}, f.bob)
	if ok, _ := f.p.CanAccess(f.Ctx, f.carol, c); !ok {
		t.Error("invited member cannot enter")
	}
	page := post("/c/{id}/invite", url.Values{"username": {"nobody here"}}, f.bob)
	if !strings.Contains(string(page.Body), `value="nobody here" aria-invalid="true"`) {
		t.Errorf("refused invite did not keep the input:\n%s", page.Body)
	}

	post("/c/{id}/topic", url.Values{"topic": {"  Pizza  "}}, f.alice)
	c, _ = f.p.Get(f.Ctx, priv)
	hist, _ := f.p.History(f.Ctx, c, 10, time.Time{}, time.Time{})
	if c.Topic != "Pizza" || len(hist) == 0 || hist[len(hist)-1].Body != "alice changed the topic to: Pizza" {
		t.Errorf("topic = %q, log = %+v", c.Topic, hist)
	}
	page, _ = f.WebGet(f.p, "/c/{id}", f.chanID(priv), f.alice)
	if !strings.Contains(string(page.Body), `name="topic" maxlength="`+strconv.Itoa(MaxTopic)+`" value="Pizza"`) {
		t.Errorf("topic form not filled in:\n%s", page.Body)
	}

	post("/c/{id}/remove", url.Values{"username": {"carol"}}, f.alice)
	if ok, _ := f.p.CanAccess(f.Ctx, f.carol, c); ok {
		t.Error("removed member can still enter")
	}
	if page, _ := f.WebGetQuery(f.p, "/c/{id}", f.chanID(priv), url.Values{"done": {"remove"}}, f.alice); !strings.Contains(string(page.Body), `<p class="notice" role="status">Removed from this chat.</p>`) {
		t.Errorf("notice missing:\n%s", page.Body)
	}
	if page, _ := f.WebGetQuery(f.p, "/c/{id}", f.chanID(priv), url.Values{"done": {"<b>made up</b>"}}, f.alice); strings.Contains(string(page.Body), "made up") {
		t.Error("an unknown notice code is shown")
	}
}

func TestWebCreate(t *testing.T) {
	f := setup(t)
	if page, err := f.WebGet(f.p, "/new", nil, f.alice); err != nil || !strings.Contains(string(page.Body), `<label for="new-name">Name</label>`) {
		t.Fatalf("form = %s, %v", page.Body, err)
	}
	tests := []struct {
		name     string
		form     url.Values
		errorMsg string
	}{
		{"bad name", url.Values{"name": {"Bad Name"}, "invite": {"bob"}}, "Channel names are 2-32 lowercase letters"},
		{"unknown invitee", url.Values{"name": {"trip"}, "invite": {"bob, ghost"}}, "No active member called &#34;ghost&#34;."},
		{"name taken", url.Values{"name": {"lobby"}}, "A channel with that name already exists."},
		{"started", url.Values{"name": {"trip"}, "invite": {"bob, @carol"}, "topic": {"Hiking"}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := f.WebPost(f.p, "/new", nil, tt.form, f.alice)
			if err != nil {
				t.Fatal(err)
			}
			if tt.errorMsg != "" {
				b := string(page.Body)
				if page.Redirect != "" || !strings.Contains(b, tt.errorMsg) || !strings.Contains(b, `value="`+tt.form.Get("name")+`"`) {
					t.Errorf("refused form = %q:\n%s", page.Redirect, b)
				}
				return
			}
			c, err := f.p.ByName(f.Ctx, "trip")
			if err != nil || page.Redirect != "/p/chat/c/"+strconv.FormatInt(c.ID, 10) || c.Kind != KindAdHoc || c.Topic != "Hiking" || c.CreatorID != f.alice {
				t.Fatalf("created %+v, redirect %q, %v", c, page.Redirect, err)
			}
			for _, u := range []int64{f.bob, f.carol} {
				if ok, _ := f.p.CanAccess(f.Ctx, u, c); !ok {
					t.Errorf("invitee %d cannot enter", u)
				}
			}
		})
	}
	if _, err := f.p.ByName(f.Ctx, "trip"); err != nil {
		t.Error("no chat created")
	}
}
