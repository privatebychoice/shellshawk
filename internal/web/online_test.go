package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/presence"
	sshsessions "go.privatebychoice.com/shellshawk/internal/sessions"
)

const origin = "https://bbs.example.net"

func csrfFrom(t *testing.T, body string) string {
	t.Helper()
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token in:\n%s", body)
	}
	return m[1]
}

func TestWhoIsOnlinePage(t *testing.T) {
	e := setup(t, false)
	ended := map[uint64]error{}
	open := func(uid int64) uint64 {
		var id uint64
		c, err := e.conns.Open(uid, "member", 0, func(cause error) { ended[id] = cause })
		if err != nil {
			t.Fatal(err)
		}
		id = c.ID()
		c.Use(presence.UseTerminal)
		return id
	}
	aliceConn, adminConn := open(e.alice), open(e.admin)
	id := func(n uint64) string { return strconv.FormatUint(n, 10) }

	// Members without the permission: no link, and the pages are refused.
	alice := e.login(t, e.alice, "alice")
	if home := e.do(req{method: "GET", path: "/home", cookie: alice}).Body.String(); strings.Contains(home, "/admin/online") {
		t.Error("member sees the Who is online link")
	}
	for _, r := range []req{
		{method: "GET", path: "/admin/online", cookie: alice},
		{method: "GET", path: "/admin/online/" + id(adminConn), cookie: alice},
		{method: "POST", path: "/admin/online/" + id(adminConn) + "/end", cookie: alice, origin: origin, form: url.Values{"confirm": {"yes"}}},
	} {
		if rec := e.do(r); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s as member = %d, want 403", r.method, r.path, rec.Code)
		}
	}
	if rec := e.do(req{method: "GET", path: "/admin/online"}); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("anonymous = %d %s", rec.Code, rec.Header().Get("Location"))
	}

	// The administrator sees both connections in an accessible table.
	admin := e.login(t, e.admin, "admin1")
	home := e.do(req{method: "GET", path: "/home", cookie: admin}).Body.String()
	if !strings.Contains(home, `<a href="/admin/online">Who is online</a>`) {
		t.Errorf("admin nav missing the link:\n%s", home)
	}
	list := e.do(req{method: "GET", path: "/admin/online", cookie: admin})
	b := list.Body.String()
	for _, want := range []string{
		"2 SSH connection(s) open. Addresses are never shown.",
		"<caption>Open SSH connections, oldest first</caption>",
		`<th scope="col">Account</th>`,
		`<tr><th scope="row">alice</th><td>1 terminal</td><td>under a minute</td>`,
		`<a href="/admin/online/` + id(aliceConn) + `">End<span class="visually-hidden"> alice's connection</span></a>`,
	} {
		if !strings.Contains(b, want) {
			t.Errorf("list missing %q in:\n%s", want, b)
		}
	}
	if list.Code != 200 || strings.Index(b, ">alice<") > strings.Index(b, ">admin1<") {
		t.Errorf("list status %d or not oldest first", list.Code)
	}

	// Confirmation page; posting without the box ticked is refused.
	confirm := e.do(req{method: "GET", path: "/admin/online/" + id(aliceConn), cookie: admin}).Body.String()
	if !strings.Contains(confirm, "End this connection? <strong>alice: 1 terminal, idle under a minute</strong>") ||
		!strings.Contains(confirm, `name="confirm" value="yes" required`) {
		t.Errorf("confirm page:\n%s", confirm)
	}
	csrf := csrfFrom(t, confirm)
	end := func(cookie *http.Cookie, conn uint64, form url.Values) *http.Response {
		return e.do(req{method: "POST", path: "/admin/online/" + id(conn) + "/end", cookie: cookie, origin: origin, form: form}).Result()
	}

	tests := []struct {
		name     string
		form     url.Values
		conn     uint64
		status   int
		location string
	}{
		{"wrong CSRF token", url.Values{"csrf": {"x"}, "confirm": {"yes"}}, aliceConn, http.StatusForbidden, ""},
		{"box not ticked", url.Values{"csrf": {csrf}}, aliceConn, http.StatusUnprocessableEntity, ""},
		{"ended", url.Values{"csrf": {csrf}, "confirm": {"yes"}}, aliceConn, http.StatusSeeOther, "/admin/online?done=ended"},
		{"already closed", url.Values{"csrf": {csrf}, "confirm": {"yes"}}, 999, http.StatusSeeOther, "/admin/online?done=gone"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := end(admin, tt.conn, tt.form)
			if res.StatusCode != tt.status || res.Header.Get("Location") != tt.location {
				t.Errorf("= %d %q, want %d %q", res.StatusCode, res.Header.Get("Location"), tt.status, tt.location)
			}
		})
	}
	var d *presence.Disconnect
	if !errors.As(ended[aliceConn], &d) || d.Message != sshsessions.EndedMessage {
		t.Errorf("alice's connection cause = %v", ended[aliceConn])
	}
	if b := e.do(req{method: "GET", path: "/admin/online?done=ended", cookie: admin}).Body.String(); !strings.Contains(b, `<p class="notice" role="status">The connection has been ended.</p>`) {
		t.Errorf("notice missing:\n%s", b)
	}
	if b := e.do(req{method: "GET", path: "/admin/online?done=<script>", cookie: admin}).Body.String(); strings.Contains(b, "notice") {
		t.Error("an unknown done code produced a notice")
	}

	// A moderator given the permission cannot end an administrator's.
	mods, _ := e.perms.GroupByName(context.Background(), perm.GroupModerator)
	if err := e.perms.Grant(context.Background(), e.admin, mods.ID, perm.SessionsManage); err != nil {
		t.Fatal(err)
	}
	mod := e.login(t, e.mod, "mod1")
	modCSRF := csrfFrom(t, e.do(req{method: "GET", path: "/admin/online", cookie: mod}).Body.String())
	res := end(mod, adminConn, url.Values{"csrf": {modCSRF}, "confirm": {"yes"}})
	if res.StatusCode != http.StatusForbidden || ended[adminConn] != nil {
		t.Errorf("moderator ending admin's = %d, ended %v", res.StatusCode, ended[adminConn])
	}
}
