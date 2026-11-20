package web

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/auth"
)

func TestInvites(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	as := e.srv.cfg.Auth
	_, adminInv, err := as.CreateInvite(ctx, e.admin, auth.InviteOptions{Note: "for the admin"})
	if err != nil {
		t.Fatal(err)
	}
	id := func(n int64) string { return strconv.FormatInt(n, 10) }

	// Members hold neither invite permission.
	alice := e.login(t, e.alice, "alice")
	if home := e.do(req{method: "GET", path: "/home", cookie: alice}).Body.String(); strings.Contains(home, "/admin/invites") {
		t.Error("member sees the Invites link")
	}
	for _, p := range []string{"/admin/invites", "/admin/invites/new"} {
		if rec := e.do(req{method: "GET", path: p, cookie: alice}); rec.Code != http.StatusForbidden {
			t.Errorf("member %s = %d", p, rec.Code)
		}
	}

	// A moderator creates invites and sees only their own.
	mod := e.login(t, e.mod, "mod1")
	if home := e.do(req{method: "GET", path: "/admin", cookie: mod}).Body.String(); !strings.Contains(home, `<a href="/admin/invites">Invites</a>`) {
		t.Error("moderator nav missing the link")
	}
	form := e.do(req{method: "GET", path: "/admin/invites/new", cookie: mod}).Body.String()
	for _, want := range []string{
		`<input type="number" id="f-uses" name="f-uses" inputmode="numeric" step="1" min="1" max="100" required value="1"`,
		`id="f-days"`, `max="90"`, `name="f-approval" value="true"`,
		`<input type="checkbox" name="f-groups" value="admin">`, `id="f-note"`,
	} {
		if !strings.Contains(form, want) {
			t.Errorf("form missing %q", want)
		}
	}
	csrf := csrfFrom(t, form)
	create := func(v url.Values) *http.Response {
		v.Set("csrf", csrf)
		return e.do(req{method: "POST", path: "/admin/invites/new", cookie: mod, origin: origin, form: v}).Result()
	}
	body := func(res *http.Response) string {
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}

	bad := create(url.Values{"f-uses": {"0"}, "f-days": {"7"}})
	if b := body(bad); bad.StatusCode != 422 || !strings.Contains(b, `aria-invalid="true"`) || !strings.Contains(b, `id="f-uses-error"`) {
		t.Errorf("invalid uses = %d:\n%s", bad.StatusCode, b)
	}
	forbidden := create(url.Values{"f-uses": {"1"}, "f-days": {"7"}, "f-groups": {"admin"}})
	if b := body(forbidden); forbidden.StatusCode != 403 || !strings.Contains(b, "Groups cannot include a group with permissions you do not have.") {
		t.Errorf("admin group = %d:\n%s", forbidden.StatusCode, b)
	}

	ok := create(url.Values{"f-uses": {"3"}, "f-days": {"2"}, "f-approval": {"true"}, "f-note": {"for <bob>"}})
	page := body(ok)
	m := regexp.MustCompile(`<p class="invite-code"><code>([^<]+)</code></p>`).FindStringSubmatch(page)
	if ok.StatusCode != 200 || m == nil || ok.Header.Get("Location") != "" || ok.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("create = %d, location %q, cache %q:\n%s", ok.StatusCode, ok.Header.Get("Location"), ok.Header.Get("Cache-Control"), page)
	}
	inv, err := as.CheckInvite(ctx, m[1])
	if err != nil || inv.MaxUses != 3 || !inv.RequireApproval || inv.Note != "for <bob>" || inv.CreatedBy != e.mod {
		t.Errorf("created invite = %+v, %v", inv, err)
	}
	for _, want := range []string{"This is the only time the code is shown.", "as user <code>new</code>", "to <code>bbs.example.net:2222</code>", "It works 3 time(s)", "new accounts need approval"} {
		if !strings.Contains(page, want) {
			t.Errorf("created page missing %q", want)
		}
	}

	list := e.do(req{method: "GET", path: "/admin/invites", cookie: mod}).Body.String()
	if !strings.Contains(list, "<caption>Your invites</caption>") || !strings.Contains(list, `<th scope="row">Invite `+id(inv.ID)+`</th><td>usable, needs approval</td><td>0 of 3</td>`) ||
		!strings.Contains(list, "<td>for &lt;bob&gt;</td>") || strings.Contains(list, "for the admin") || strings.Contains(list, "Created by") {
		t.Errorf("moderator list:\n%s", list)
	}

	// The administrator sees every invite and who created it.
	admin := e.login(t, e.admin, "admin1")
	all := e.do(req{method: "GET", path: "/admin/invites", cookie: admin}).Body.String()
	if !strings.Contains(all, "<caption>All invites</caption>") || !strings.Contains(all, "<td>mod1</td>") || !strings.Contains(all, "<td>admin1</td><td>for the admin</td>") {
		t.Errorf("admin list:\n%s", all)
	}

	// Revoking: only invites you may see, confirmed.
	if rec := e.do(req{method: "GET", path: "/admin/invites/" + id(adminInv.ID) + "/revoke", cookie: mod}); rec.Code != 303 || rec.Header().Get("Location") != "/admin/invites?done=gone" {
		t.Errorf("moderator revoking the admin's invite = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if b := e.do(req{method: "GET", path: "/admin/invites/" + id(inv.ID) + "/revoke", cookie: mod}).Body.String(); !strings.Contains(b, "Revoke invite "+id(inv.ID)+" (0 of 3 used") {
		t.Errorf("revoke confirmation:\n%s", b)
	}
	revoke := func(invID int64, v url.Values) *http.Response {
		v.Set("csrf", csrf)
		return e.do(req{method: "POST", path: "/admin/invites/" + id(invID) + "/revoke", cookie: mod, origin: origin, form: v}).Result()
	}
	tests := []struct {
		name     string
		inv      int64
		form     url.Values
		status   int
		location string
	}{
		{"not confirmed", inv.ID, url.Values{}, 422, ""},
		{"someone else's", adminInv.ID, url.Values{"confirm": {"yes"}}, 303, "/admin/invites?done=gone"},
		{"own", inv.ID, url.Values{"confirm": {"yes"}}, 303, "/admin/invites?done=revoked"},
		{"again", inv.ID, url.Values{"confirm": {"yes"}}, 303, "/admin/invites?done=gone"},
	}
	for _, tt := range tests {
		t.Run("revoke "+tt.name, func(t *testing.T) {
			res := revoke(tt.inv, tt.form)
			if res.StatusCode != tt.status || res.Header.Get("Location") != tt.location {
				t.Errorf("= %d %q, want %d %q", res.StatusCode, res.Header.Get("Location"), tt.status, tt.location)
			}
		})
	}
	if _, err := as.CheckInvite(ctx, m[1]); err == nil {
		t.Error("revoked invite still works")
	}
	if _, err := as.CheckInvite(ctx, ""); err == nil {
		t.Error("empty code accepted")
	}
	after := e.do(req{method: "GET", path: "/admin/invites?done=revoked", cookie: mod}).Body.String()
	if !strings.Contains(after, "The invite has been revoked.") || !strings.Contains(after, "<td>revoked, needs approval</td>") {
		t.Errorf("after revoking:\n%s", after)
	}
}
