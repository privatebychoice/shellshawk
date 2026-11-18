package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/perm"
)

func TestUsersPages(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	as, db := e.srv.cfg.Auth, e.srv.cfg.Auth.DB()
	if _, err := db.Exec(`UPDATE users SET email = 'alice@example.org' WHERE id = ?`, e.alice); err != nil {
		t.Fatal(err)
	}
	id := func(n int64) string { return strconv.FormatInt(n, 10) }
	status := func(uid int64) string { u, _ := as.UserByID(ctx, uid); return u.Status }

	// Members and moderators hold neither permission.
	for name, uid := range map[string]int64{"alice": e.alice, "mod1": e.mod} {
		c := e.login(t, uid, name)
		if home := e.do(req{method: "GET", path: "/home", cookie: c}).Body.String(); strings.Contains(home, `href="/admin/users"`) {
			t.Errorf("%s sees the Users link", name)
		}
		if rec := e.do(req{method: "GET", path: "/admin/users/" + id(e.admin), cookie: c}); rec.Code != http.StatusForbidden {
			t.Errorf("%s = %d", name, rec.Code)
		}
	}

	admin := e.login(t, e.admin, "admin1")
	if home := e.do(req{method: "GET", path: "/home", cookie: admin}).Body.String(); !strings.Contains(home, `<a href="/admin/users">Users</a>`) {
		t.Error("admin nav missing the link")
	}
	if b := e.do(req{method: "GET", path: "/admin/users", cookie: admin}).Body.String(); strings.Contains(b, "<table") || !strings.Contains(b, `<input type="search" id="q" name="q"`) {
		t.Errorf("search page before searching:\n%s", b)
	}
	everyone := e.do(req{method: "GET", path: "/admin/users?q=", cookie: admin}).Body.String()
	if !strings.Contains(everyone, "3 match(es).") || !strings.Contains(everyone, `<th scope="row"><a href="/admin/users/`+id(e.alice)+`">alice</a></th><td>active</td>`) {
		t.Errorf("everyone:\n%s", everyone)
	}
	if b := e.do(req{method: "GET", path: "/admin/users?q=AL", cookie: admin}).Body.String(); !strings.Contains(b, "1 match(es).") || !strings.Contains(b, "starts with &ldquo;AL&rdquo;") {
		t.Errorf("prefix search:\n%s", b)
	}
	if b := e.do(req{method: "GET", path: "/admin/users?q=%25", cookie: admin}).Body.String(); !strings.Contains(b, "0 match(es).") {
		t.Errorf("wildcard search should match nothing:\n%s", b)
	}

	page := e.do(req{method: "GET", path: "/admin/users/" + id(e.alice), cookie: admin}).Body.String()
	for _, want := range []string{
		"<dt>Status</dt><dd>active</dd>", "<dt>Groups</dt><dd>member</dd>",
		`action="/admin/users/` + id(e.alice) + `/lock"`, "Show email address",
		`<label for="add-group">Add to a group</label>`, `<label for="remove-group">Remove from a group</label>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("user page missing %q", want)
		}
	}
	if strings.Contains(page, "alice@example.org") {
		t.Error("email shown without asking")
	}
	csrf := csrfFrom(t, page)
	post := func(uid int64, action string, v url.Values) (int, string, string) {
		v.Set("csrf", csrf)
		rec := e.do(req{method: "POST", path: "/admin/users/" + id(uid) + "/" + action, cookie: admin, origin: origin, form: v})
		return rec.Code, rec.Header().Get("Location"), rec.Body.String()
	}

	// Showing the email address is a POST, answered with the page, and audited.
	st, loc, b := post(e.alice, "email", url.Values{})
	var viewed int
	db.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'admin.viewed.email' AND target_id = ?`, id(e.alice)).Scan(&viewed)
	if st != 200 || loc != "" || !strings.Contains(b, "Email address: <strong>alice@example.org</strong>") || viewed != 1 {
		t.Errorf("email = %d %q, audited %d:\n%s", st, loc, viewed, b)
	}
	if rec := e.do(req{method: "GET", path: "/admin/users/" + id(e.alice) + "/email", cookie: admin}); rec.Code == 200 {
		t.Error("email can be shown by a GET")
	}

	mods, _ := e.perms.GroupByName(ctx, perm.GroupModerator)
	admins, _ := e.perms.GroupByName(ctx, perm.GroupAdmin)
	tests := []struct {
		name     string
		uid      int64
		action   string
		form     url.Values
		status   int
		location string
		want     string
	}{
		{"lock unconfirmed", e.alice, "lock", url.Values{}, 422, "", "Tick the box to confirm"},
		{"lock", e.alice, "lock", url.Values{"confirm": {"yes"}}, 303, "/admin/users/" + id(e.alice) + "?done=locked", ""},
		{"lock again", e.alice, "lock", url.Values{"confirm": {"yes"}}, 409, "", "The account has changed since the page was shown."},
		{"unlock", e.alice, "unlock", url.Values{"confirm": {"yes"}}, 303, "/admin/users/" + id(e.alice) + "?done=unlocked", ""},
		{"lock yourself", e.admin, "lock", url.Values{"confirm": {"yes"}}, 409, "", "You cannot do that to your own account."},
		{"your own email", e.admin, "email", url.Values{}, 409, "", "You cannot do that to your own account."},
		{"add to a group", e.alice, "groups/add", url.Values{"group": {id(mods.ID)}}, 303, "/admin/users/" + id(e.alice) + "?done=added", ""},
		{"no group chosen", e.alice, "groups/add", url.Values{}, 422, "", "Choose a group."},
		{"remove the last administrator", e.admin, "groups/remove", url.Values{"group": {id(admins.ID)}}, 409, "", "without an active administrator"},
		{"unknown account", 999, "lock", url.Values{"confirm": {"yes"}}, 404, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, loc, body := post(tt.uid, tt.action, tt.form)
			if st != tt.status || loc != tt.location || !strings.Contains(body, tt.want) {
				t.Errorf("= %d %q, want %d %q containing %q", st, loc, tt.status, tt.location, tt.want)
			}
		})
	}
	if status(e.alice) != auth.StatusActive {
		t.Errorf("alice = %s", status(e.alice))
	}
	if groups, _ := e.perms.UserGroups(ctx, e.alice); strings.Join(groups, ",") != "member,moderator" {
		t.Errorf("alice's groups = %v", groups)
	}
	self := e.do(req{method: "GET", path: "/admin/users/" + id(e.admin), cookie: admin}).Body.String()
	if !strings.Contains(self, "You cannot lock your own account") || strings.Contains(self, `/lock"`) {
		t.Errorf("own page offers locking:\n%s", self)
	}

	// An erasure request can be cancelled.
	if _, err := e.srv.cfg.Privacy.RequestErasure(ctx, e.alice, false); err != nil {
		t.Fatal(err)
	}
	erasing := e.do(req{method: "GET", path: "/admin/users/" + id(e.alice), cookie: admin}).Body.String()
	if !strings.Contains(erasing, "<dt>Erasure</dt><dd>The member asked for this account to be erased") || !strings.Contains(erasing, "/cancel-erasure") {
		t.Errorf("erasing page:\n%s", erasing)
	}
	if st, loc, _ := post(e.alice, "cancel-erasure", url.Values{"confirm": {"yes"}}); st != 303 || loc != "/admin/users/"+id(e.alice)+"?done=cancelled" || status(e.alice) != auth.StatusActive {
		t.Errorf("cancel erasure = %d %q, status %s", st, loc, status(e.alice))
	}
}
