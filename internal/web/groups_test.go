package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
)

func TestGroupsPages(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	id := func(n int64) string { return strconv.FormatInt(n, 10) }

	mod := e.login(t, e.mod, "mod1")
	if home := e.do(req{method: "GET", path: "/home", cookie: mod}).Body.String(); strings.Contains(home, "/admin/groups") {
		t.Error("moderator sees the Groups link")
	}
	if rec := e.do(req{method: "GET", path: "/admin/groups", cookie: mod}); rec.Code != http.StatusForbidden {
		t.Errorf("moderator = %d", rec.Code)
	}

	admin := e.login(t, e.admin, "admin1")
	if home := e.do(req{method: "GET", path: "/admin", cookie: admin}).Body.String(); !strings.Contains(home, `<a href="/admin/groups">Groups</a>`) {
		t.Error("admin nav missing the link")
	}
	admins, _ := e.perms.GroupByName(ctx, perm.GroupAdmin)
	list := e.do(req{method: "GET", path: "/admin/groups", cookie: admin}).Body.String()
	for _, want := range []string{
		"<caption>Groups</caption>",
		`<th scope="row"><a href="/admin/groups/` + id(admins.ID) + `">admin</a></th>`,
		`<input type="text" id="f-name" name="f-name" maxlength="32" required`,
		`<span class="meta" id="f-name-rules">2 to 32 characters, required</span>`,
	} {
		if !strings.Contains(list, want) {
			t.Errorf("list missing %q", want)
		}
	}
	csrf := csrfFrom(t, list)
	post := func(path string, v url.Values) (int, string, string) {
		v.Set("csrf", csrf)
		rec := e.do(req{method: "POST", path: path, cookie: admin, origin: origin, form: v})
		return rec.Code, rec.Header().Get("Location"), rec.Body.String()
	}

	createTests := []struct {
		name   string
		group  string
		status int
		want   string
	}{
		{"invalid name", "Bad Name", 422, `<p class="error" id="f-name-error">Name must be lowercase letters, digits, &#39;_&#39; or &#39;-&#39;, starting with a letter.</p>`},
		{"too short", "h", 422, "Name must be at least 2 characters."},
		{"taken", "member", 422, "Name is already used by another group."},
		{"created", "helpers", 303, ""},
	}
	for _, tt := range createTests {
		t.Run("create "+tt.name, func(t *testing.T) {
			st, _, body := post("/admin/groups/new", url.Values{"f-name": {tt.group}, "f-desc": {"People who help"}})
			if st != tt.status || !strings.Contains(body, tt.want) {
				t.Errorf("= %d, want %d containing %q:\n%s", st, tt.status, tt.want, body)
			}
		})
	}
	helpers, err := e.perms.GroupByName(ctx, "helpers")
	if err != nil {
		t.Fatal(err)
	}
	gp := "/admin/groups/" + id(helpers.ID)
	page := e.do(req{method: "GET", path: gp + "?done=created", cookie: admin}).Body.String()
	for _, want := range []string{
		"The group has been created.", "<p>People who help</p>", "This group has no permissions.", "This group has no members.",
		`<option value="notes.secret">notes.secret: secret</option>`, "Yes, delete helpers.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("group page missing %q", want)
		}
	}

	tests := []struct {
		name     string
		path     string
		form     url.Values
		status   int
		location string
		want     string
	}{
		{"grant", gp + "/grant", url.Values{"perm": {"notes.secret"}}, 303, gp + "?done=granted", ""},
		{"grant an unknown permission", gp + "/grant", url.Values{"perm": {"no.such"}}, 422, "", "That permission does not exist."},
		{"add a member", gp + "/members/add", url.Values{"username": {"ALICE"}}, 303, gp + "?done=added", ""},
		{"add nobody", gp + "/members/add", url.Values{"username": {"ghost"}}, 422, "", `<p class="error" id="add-member-error">There is no account with that username.</p>`},
		{"remove a member", gp + "/members/remove", url.Values{"user": {id(e.alice)}}, 303, gp + "?done=removed", ""},
		{"revoke", gp + "/revoke", url.Values{"perm": {"notes.secret"}}, 303, gp + "?done=revoked", ""},
		{"revoke the administrators' core.admin", "/admin/groups/" + id(admins.ID) + "/revoke", url.Values{"perm": {perm.Admin}}, 409, "", "Built-in groups cannot be changed that way."},
		{"remove the last administrator", "/admin/groups/" + id(admins.ID) + "/members/remove", url.Values{"user": {id(e.admin)}}, 409, "", "without an active administrator"},
		{"delete a built-in group", "/admin/groups/" + id(admins.ID) + "/delete", url.Values{"confirm": {"yes"}}, 409, "", "Built-in groups cannot be changed that way."},
		{"delete unconfirmed", gp + "/delete", url.Values{}, 422, "", "Tick the box to confirm"},
		{"delete", gp + "/delete", url.Values{"confirm": {"yes"}}, 303, "/admin/groups?done=deleted", ""},
		{"deleted group", gp + "/grant", url.Values{"perm": {"notes.secret"}}, 404, "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, loc, body := post(tt.path, tt.form)
			if st != tt.status || loc != tt.location || !strings.Contains(body, tt.want) {
				t.Errorf("= %d %q, want %d %q containing %q", st, loc, tt.status, tt.location, tt.want)
			}
		})
	}
	adminPage := e.do(req{method: "GET", path: "/admin/groups/" + id(admins.ID), cookie: admin}).Body.String()
	if !strings.Contains(adminPage, "This group is built in.") || strings.Contains(adminPage, "/delete") {
		t.Errorf("built-in group page offers deleting:\n%s", adminPage)
	}
	var audits int
	e.srv.cfg.Auth.DB().QueryRow(`SELECT count(*) FROM audit_log WHERE action LIKE 'group.%' AND actor_id = ?`, e.admin).Scan(&audits)
	if audits != 6 { // created, granted, added, removed, revoked, deleted
		t.Errorf("audit entries = %d", audits)
	}
}
