package messages

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
)

func idOf(n int64) map[string]string { return map[string]string{"id": strconv.FormatInt(n, 10)} }

func TestWebFolders(t *testing.T) {
	f := setup(t)
	toBob, _ := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "Hello <bob>", Body: "hi"})
	f.p.Send(f.Ctx, f.bob, Draft{To: "alice", Subject: "Answer", Body: "yes"})
	gone, _ := f.p.Send(f.Ctx, f.carol, Draft{To: "bob", Subject: "Old news", Body: "x"})
	if err := f.p.Delete(f.Ctx, f.bob, gone, Inbox); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name, path string
		want, not  []string
	}{
		{"inbox", "/", []string{
			`<a href="/p/messages/" aria-current="page">Inbox (1 unread)</a>`, "Deleted (1)", "1 unread, 0 read.",
			`class="unread">New: <a href="/p/messages/m/` + strconv.FormatInt(toBob, 10) + `">Hello &lt;bob&gt;</a>`, "from alice",
			`<a href="/p/messages/new">Write a message</a>`,
		}, []string{"Old news", "Answer"}},
		{"sent", "/sent", []string{`aria-current="page">Sent</a>`, "Answer", "to alice", "?folder=sent"}, []string{"New: ", "Hello"}},
		{"deleted", "/deleted", []string{"Old news", "removed permanently after 30 days", "?folder=deleted",
			"Yes, delete all 1 message(s) here permanently.", `action="/p/messages/deleted/empty"`}, []string{"Hello"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := f.WebGet(f.p, tt.path, nil, f.bob)
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
	if page, _ := f.WebGetQuery(f.p, "/", nil, url.Values{"done": {"<i>x</i>"}}, f.bob); strings.Contains(string(page.Body), "notice") {
		t.Error("unknown notice code shown")
	}
	if page, _ := f.WebGet(f.p, "/deleted", nil, f.alice); strings.Contains(string(page.Body), "Empty the Deleted folder") {
		t.Error("empty form shown for an empty Deleted folder")
	}
}

func TestWebMessagePage(t *testing.T) {
	f := setup(t)
	toBob, _ := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "Plans", Body: "**Lunch?**"})
	self, _ := f.p.Send(f.Ctx, f.bob, Draft{To: "bob", Subject: "Note to self", Body: "x"})
	base := "/p/messages/m/"

	page, err := f.WebGet(f.p, "/m/{id}", idOf(toBob), f.bob)
	b := string(page.Body)
	if err != nil || page.Title != "Plans" || !strings.Contains(b, "<strong>Lunch?</strong>") || !strings.Contains(b, `href="/p/messages/new?reply=`) ||
		!strings.Contains(b, `action="`+base+strconv.FormatInt(toBob, 10)+`/delete"`) || strings.Contains(b, "Delete permanently") {
		t.Fatalf("received message = %s, %v", b, err)
	}
	if c, _ := f.p.Count(f.Ctx, f.bob); c.Unread != 1 { // the note to self is still unread
		t.Errorf("unread = %d after opening", c.Unread)
	}
	page, _ = f.WebGet(f.p, "/m/{id}", idOf(toBob), f.alice)
	if b := string(page.Body); strings.Contains(b, "Reply") || !strings.Contains(b, "Remove from Sent") || !strings.Contains(b, `name="folder" value="sent"`) {
		t.Errorf("sender's view:\n%s", b)
	}
	page, _ = f.WebGetQuery(f.p, "/m/{id}", idOf(self), url.Values{"folder": {"sent"}}, f.bob)
	if b := string(page.Body); !strings.Contains(b, "Remove from Sent") || !strings.Contains(b, "Back to Sent") {
		t.Errorf("note to self opened from Sent:\n%s", b)
	}
	if _, err := f.WebGet(f.p, "/m/{id}", idOf(toBob), f.carol); !errors.Is(err, plugin.ErrWebNotFound) {
		t.Errorf("someone else's message: err = %v", err)
	}
}

func TestWebActions(t *testing.T) {
	f := setup(t)
	m1, _ := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "One", Body: "1"})
	m2, _ := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "Two", Body: "2"})
	yes := url.Values{"confirm": {"yes"}}
	folders := func(user int64, folder string) []int64 {
		list, _ := f.p.List(f.Ctx, user, folder)
		var ids []int64
		for _, m := range list {
			ids = append(ids, m.ID)
		}
		return ids
	}

	steps := []struct {
		name, path string
		user, id   int64
		form       url.Values
		redirect   string
		status     int // expected WebError status; 404 = not found
		check      func() bool
	}{
		{"delete moves to Deleted", "/m/{id}/delete", f.bob, m1, url.Values{}, "/p/messages/?done=deleted", 0,
			func() bool {
				return slices.Contains(folders(f.bob, Deleted), m1) && !slices.Contains(folders(f.bob, Inbox), m1)
			}},
		{"restore", "/m/{id}/restore", f.bob, m1, url.Values{}, "/p/messages/deleted?done=restored", 0,
			func() bool { return slices.Contains(folders(f.bob, Inbox), m1) }},
		{"not someone else's", "/m/{id}/delete", f.carol, m1, url.Values{}, "", 404, nil},
		{"delete permanently needs the box", "/m/{id}/forever", f.bob, m2, url.Values{}, "", 400, nil},
		{"delete permanently only from Deleted", "/m/{id}/forever", f.bob, m2, yes, "", 404, nil},
		{"delete m2", "/m/{id}/delete", f.bob, m2, url.Values{}, "/p/messages/?done=deleted", 0, nil},
		{"delete permanently", "/m/{id}/forever", f.bob, m2, yes, "/p/messages/deleted?done=forever", 0,
			func() bool { return !slices.Contains(folders(f.bob, Deleted), m2) }},
		{"remove from Sent needs the box", "/m/{id}/delete", f.alice, m1, url.Values{"folder": {"sent"}}, "", 400, nil},
		{"remove from Sent", "/m/{id}/delete", f.alice, m1, url.Values{"folder": {"sent"}, "confirm": {"yes"}}, "/p/messages/sent?done=removed", 0,
			func() bool {
				return !slices.Contains(folders(f.alice, Sent), m1) && slices.Contains(folders(f.bob, Inbox), m1)
			}},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			page, err := f.WebPost(f.p, st.path, idOf(st.id), st.form, st.user)
			var we *plugin.WebError
			switch {
			case st.status == 404:
				if !errors.Is(err, plugin.ErrWebNotFound) {
					t.Errorf("err = %v, want not found", err)
				}
			case st.status != 0:
				if !errors.As(err, &we) || we.Status != st.status {
					t.Errorf("err = %v, want %d", err, st.status)
				}
			case err != nil || page.Redirect != st.redirect:
				t.Errorf("result = %q, %v; want %q", page.Redirect, err, st.redirect)
			case st.check != nil && !st.check():
				t.Error("the action did not take effect")
			}
		})
	}

	// Empty the Deleted folder.
	f.p.Delete(f.Ctx, f.bob, m1, Inbox)
	var we *plugin.WebError
	if _, err := f.WebPost(f.p, "/deleted/empty", nil, url.Values{}, f.bob); !errors.As(err, &we) || we.Status != http.StatusBadRequest {
		t.Errorf("empty without the box: err = %v", err)
	}
	if page, err := f.WebPost(f.p, "/deleted/empty", nil, yes, f.bob); err != nil || page.Redirect != "/p/messages/deleted?done=emptied" || len(folders(f.bob, Deleted)) != 0 {
		t.Errorf("empty = %q, %v; left %v", page.Redirect, err, folders(f.bob, Deleted))
	}
}

func TestWebCompose(t *testing.T) {
	f := setup(t)
	f.c.Add(f.Ctx, f.alice, "bob", "")
	f.c.Add(f.Ctx, f.alice, "carol", "")
	g, _ := f.c.CreateGroup(f.Ctx, f.alice, "team")
	f.c.AddToGroup(f.Ctx, f.alice, g, f.bob)
	f.c.AddToGroup(f.Ctx, f.alice, g, f.carol)
	orig, _ := f.p.Send(f.Ctx, f.bob, Draft{To: "alice", Subject: "Lunch?", Body: "Pizza\nor soup"})

	page, err := f.WebGet(f.p, "/new", nil, f.alice)
	if b := string(page.Body); err != nil || !strings.Contains(b, `<legend>Also send to these contact groups</legend>`) ||
		!strings.Contains(b, `name="groups" value="team"> team (2)`) || !strings.Contains(b, `<textarea id="msg-body" name="body"`) {
		t.Fatalf("form = %s, %v", b, err)
	}
	page, _ = f.WebGetQuery(f.p, "/new", nil, url.Values{"reply": {strconv.FormatInt(orig, 10)}}, f.alice)
	if b := string(page.Body); page.Title != "Reply" || !strings.Contains(b, `value="bob"`) || !strings.Contains(b, `value="Re: Lunch?"`) ||
		!strings.Contains(b, "bob wrote:\n\n&gt; Pizza\n&gt; or soup") || !strings.Contains(b, `name="parent" value="`+strconv.FormatInt(orig, 10)+`"`) {
		t.Errorf("reply form:\n%s", b)
	}
	for _, q := range []string{strconv.FormatInt(orig, 10), "x"} {
		if _, err := f.WebGetQuery(f.p, "/new", nil, url.Values{"reply": {q}}, f.carol); !errors.Is(err, plugin.ErrWebNotFound) {
			t.Errorf("reply to %s by someone else: err = %v", q, err)
		}
	}

	tests := []struct {
		name  string
		form  url.Values
		field string // error shown at this field ("" = sent)
		msg   string
	}{
		{"nobody", url.Values{"subject": {"Hi"}, "body": {"x"}}, "msg-to-error", "Add at least one recipient."},
		{"unknown", url.Values{"to": {"ghost"}, "subject": {"Hi"}, "body": {"x"}}, "msg-to-error", "Unknown recipient(s): ghost."},
		{"no subject", url.Values{"to": {"bob"}, "subject": {" "}, "body": {"x"}}, "msg-subject-error", "The subject must be"},
		{"empty body", url.Values{"to": {"bob"}, "subject": {"Hi"}, "body": {"  "}}, "msg-body-error", "The message must be"},
		{"control characters", url.Values{"to": {"bob"}, "subject": {"Hi"}, "body": {"a\x1b[2Jb"}}, "msg-body-error", "The message contains control characters."},
		{"to a contact group, as a reply", url.Values{"groups": {"team"}, "subject": {"Re: Lunch?"}, "body": {"Soup\r\nplease"}, "parent": {strconv.FormatInt(orig, 10)}}, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := f.WebPost(f.p, "/new", nil, tt.form, f.alice)
			if err != nil {
				t.Fatal(err)
			}
			b := string(page.Body)
			if tt.field != "" {
				kept := strings.Contains(b, ">"+tt.form.Get("body")+"</textarea>") // what was typed is kept
				if page.Redirect != "" || !strings.Contains(b, `id="`+tt.field+`">`+tt.msg) || !strings.Contains(b, `aria-invalid="true"`) || !kept {
					t.Errorf("refused form = %q:\n%s", page.Redirect, b)
				}
				return
			}
			if page.Redirect != "/p/messages/sent?done=sent" {
				t.Fatalf("send = %q:\n%s", page.Redirect, b)
			}
		})
	}
	for _, u := range []int64{f.bob, f.carol} {
		list, _ := f.p.List(f.Ctx, u, Inbox)
		if len(list) == 0 || list[0].Subject != "Re: Lunch?" {
			t.Fatalf("user %d inbox = %+v", u, list)
		}
		m, _ := f.p.Read(f.Ctx, u, list[0].ID)
		if m.Body != "Soup\nplease" || m.ParentID != orig {
			t.Errorf("received body %q, parent %d", m.Body, m.ParentID)
		}
	}

	// A forged parent the sender cannot see is refused, keeping the text.
	page, _ = f.WebPost(f.p, "/new", nil, url.Values{"to": {"bob"}, "subject": {"Hi"}, "body": {"x"}, "parent": {"9999"}}, f.carol)
	if b := string(page.Body); !strings.Contains(b, "no longer exists") || strings.Contains(b, `name="parent"`) {
		t.Errorf("forged parent:\n%s", b)
	}

	// Without messages.send: the routes need it and the link is gone.
	for _, r := range f.p.Manifest().Web {
		if r.Path == "/new" && !slices.Equal(r.AnyOf, []string{PermSend}) {
			t.Errorf("%s /new needs %v", r.Method, r.AnyOf)
		}
	}
	member, _ := f.Perms.GroupByName(f.Ctx, perm.GroupMember)
	f.Perms.Revoke(f.Ctx, f.Admin, member.ID, PermSend)
	if page, _ := f.WebGet(f.p, "/", nil, f.bob); strings.Contains(string(page.Body), "Write a message") {
		t.Error("write link shown without messages.send")
	}
	if page, _ := f.WebGet(f.p, "/m/{id}", idOf(orig), f.alice); strings.Contains(string(page.Body), "?reply=") {
		t.Error("reply link shown without messages.send")
	}
}
