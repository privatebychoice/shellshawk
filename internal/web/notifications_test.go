package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/notify"
)

func TestNotificationsPage(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	add := func(user int64, kind, text, ref string) string {
		t.Helper()
		id, ok, err := e.notify.Add(ctx, notify.New{UserID: user, Kind: kind, ActorID: e.admin, Text: text, Ref: ref})
		if err != nil || !ok {
			t.Fatal(ok, err)
		}
		return strconv.FormatInt(id, 10)
	}
	note := add(e.alice, "notes:note", "read this", "5")
	ping := add(e.alice, "notes:ping", "hello <b>", "")
	adminNote := add(e.admin, "notes:note", "not alice's", "6")

	if rec := e.do(req{method: "GET", path: "/notifications"}); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("anonymous = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	alice := e.login(t, e.alice, "alice")
	get := func(path string) string {
		t.Helper()
		rec := e.do(req{method: "GET", path: path, cookie: alice})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		return rec.Body.String()
	}

	home := get("/home")
	for _, want := range []string{`<a href="/notifications">Notifications (2 new)</a>`, `<a href="/notifications">You have 2 new notifications.</a>`} {
		if !strings.Contains(home, want) {
			t.Errorf("home missing %q\n%s", want, home)
		}
	}
	list := get("/notifications")
	for _, want := range []string{
		"You have 2 notification(s), 2 new.",
		`<strong>New:</strong> Pings, from admin1: hello &lt;b&gt; <span class="meta">just now</span>`,
		`Notes, from admin1: read this <span class="meta">just now</span>`,
		`action="/notifications/` + note + `/open"`,
		`<span class="visually-hidden"> notification: Notes, from admin1: read this</span>`,
		`action="/notifications/seen"`, "Yes, delete all my notifications",
	} {
		if !strings.Contains(list, want) {
			t.Errorf("list missing %q\n%s", want, list)
		}
	}
	if strings.Contains(list, "/notifications/"+ping+"/open") || strings.Contains(list, "not alice's") || strings.Contains(list, `<a href="/notifications/`+note) {
		t.Errorf("list shows a link with no web page, or another member's notification\n%s", list)
	}

	csrf := csrfFrom(t, list)
	post := func(path string, form url.Values) *http.Response {
		if form == nil {
			form = url.Values{}
		}
		if form.Get("csrf") == "" {
			form.Set("csrf", csrf)
		}
		return e.do(req{method: "POST", path: path, cookie: alice, origin: origin, form: form}).Result()
	}
	tests := []struct {
		name, method, path string
		form               url.Values
		status             int
		where              string // Location of a redirect
		newLeft, left      int    // after this step; the steps run in order
	}{
		{"an old GET link marks nothing", "GET", "/notifications/" + note + "/open", nil, http.StatusSeeOther, "/notifications", 2, 2},
		{"open without CSRF", "POST", "/notifications/" + note + "/open", url.Values{"csrf": {"wrong"}}, http.StatusForbidden, "", 2, 2},
		{"open a note: its page", "POST", "/notifications/" + note + "/open", nil, http.StatusSeeOther, "/p/notes/n/5", 1, 2},
		{"open a ping: no web page", "POST", "/notifications/" + ping + "/open", nil, http.StatusSeeOther, "/notifications?done=no-web", 0, 2},
		{"open another member's", "POST", "/notifications/" + adminNote + "/open", nil, http.StatusSeeOther, "/notifications?done=gone", 0, 2},
		{"delete without CSRF", "POST", "/notifications/" + ping + "/delete", url.Values{"csrf": {"wrong"}}, http.StatusForbidden, "", 0, 2},
		{"delete another member's", "POST", "/notifications/" + adminNote + "/delete", nil, http.StatusSeeOther, "/notifications?done=gone", 0, 2},
		{"delete one", "POST", "/notifications/" + ping + "/delete", nil, http.StatusSeeOther, "/notifications?done=deleted", 0, 1},
		{"delete all, unconfirmed", "POST", "/notifications/clear", nil, http.StatusUnprocessableEntity, "", 0, 1},
		{"delete all", "POST", "/notifications/clear", url.Values{"confirm": {"yes"}}, http.StatusSeeOther, "/notifications?done=cleared", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var res *http.Response
			if tt.method == "GET" {
				res = e.do(req{method: "GET", path: tt.path, cookie: alice}).Result()
			} else {
				res = post(tt.path, tt.form)
			}
			if res.StatusCode != tt.status || res.Header.Get("Location") != tt.where {
				t.Errorf("= %d %q, want %d %q", res.StatusCode, res.Header.Get("Location"), tt.status, tt.where)
			}
			if n, _ := e.notify.CountUnseen(ctx, e.alice); n != tt.newLeft {
				t.Errorf("%d new, want %d", n, tt.newLeft)
			}
			if all, _ := e.notify.List(ctx, e.alice); len(all) != tt.left {
				t.Errorf("%d left, want %d", len(all), tt.left)
			}
		})
	}
	if n, _ := e.notify.CountUnseen(ctx, e.admin); n != 1 {
		t.Errorf("admin's notification touched: %d new", n)
	}

	add(e.alice, "notes:ping", "again", "")
	if res := post("/notifications/seen", nil); res.Header.Get("Location") != "/notifications?done=seen" {
		t.Errorf("mark all seen = %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	if n, _ := e.notify.CountUnseen(ctx, e.alice); n != 0 {
		t.Errorf("%d new after marking all seen", n)
	}
	if home := get("/home"); !strings.Contains(home, `<a href="/notifications">Notifications</a>`) || strings.Contains(home, "new notification") {
		t.Errorf("home with nothing new:\n%s", home)
	}
}

func TestNotificationSettingsPage(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	alice := e.login(t, e.alice, "alice")
	body := e.do(req{method: "GET", path: "/notifications/settings", cookie: alice}).Body.String()
	for _, want := range []string{
		`name="f-between" value="true" checked`, "Over SSH, show new notifications between screens",
		`name="f-kind0" value="true" checked`, "Receive notifications for: Notes", "A note for you.",
		`name="f-kind1" value="true" checked`, "Receive notifications for: Pings",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("settings missing %q\n%s", want, body)
		}
	}

	// Untick "between screens" and Pings; Notes stays on.
	form := url.Values{"csrf": {csrfFrom(t, body)}, "f-kind0": {"true"}}
	rec := e.do(req{method: "POST", path: "/notifications/settings", cookie: alice, origin: origin, form: form})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/notifications?done=saved" {
		t.Fatalf("save = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	on, _ := e.notify.Settings(ctx, e.alice)
	if !on["notes:note"] || on["notes:ping"] {
		t.Errorf("settings = %v", on)
	}
	if p, _ := e.prefs.Get(ctx, e.alice); p.Notifications {
		t.Error("between screens still on")
	}
	if !strings.Contains(e.do(req{method: "GET", path: "/notifications?done=saved", cookie: alice}).Body.String(), "Your notification settings have been saved.") {
		t.Error("no confirmation")
	}
	form.Set("csrf", "wrong")
	if rec := e.do(req{method: "POST", path: "/notifications/settings", cookie: alice, origin: origin, form: form}); rec.Code != http.StatusForbidden {
		t.Errorf("without CSRF = %d", rec.Code)
	}
}
