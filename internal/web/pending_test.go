package web

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/auth"
)

func TestPendingAccounts(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	as := e.srv.cfg.Auth
	pending := func(name string, groups ...string) int64 {
		t.Helper()
		code, _, err := as.CreateInvite(ctx, e.admin, auth.InviteOptions{RequireApproval: true, Groups: groups})
		if err != nil {
			t.Fatal(err)
		}
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		k, _ := ssh.NewSignerFromKey(priv)
		u, err := as.Register(ctx, code, auth.Registration{Username: name, Password: "a long enough test passphrase",
			PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k.PublicKey())))})
		if err != nil || u.Status != auth.StatusPending {
			t.Fatalf("register %s = %+v, %v", name, u, err)
		}
		return u.ID
	}
	bob, carol, boss := pending("bob"), pending("carol"), pending("boss", "admin")
	id := func(n int64) string { return strconv.FormatInt(n, 10) }
	status := func(uid int64) string {
		u, err := as.UserByID(ctx, uid)
		if errors.Is(err, auth.ErrNotFound) {
			return "deleted"
		}
		return u.Status
	}

	// Members cannot approve; moderators can (by default).
	alice := e.login(t, e.alice, "alice")
	if home := e.do(req{method: "GET", path: "/home", cookie: alice}).Body.String(); strings.Contains(home, "/admin/pending") {
		t.Error("member sees the Approvals link")
	}
	for _, r := range []req{
		{method: "GET", path: "/admin/pending", cookie: alice},
		{method: "POST", path: "/admin/pending/" + id(bob) + "/approve", cookie: alice, origin: origin, form: url.Values{}},
	} {
		if rec := e.do(r); rec.Code != http.StatusForbidden {
			t.Errorf("member %s %s = %d", r.method, r.path, rec.Code)
		}
	}

	mod := e.login(t, e.mod, "mod1")
	if home := e.do(req{method: "GET", path: "/home", cookie: mod}).Body.String(); !strings.Contains(home, `<a href="/admin/pending">Approvals</a>`) {
		t.Error("moderator nav missing the link")
	}
	page := e.do(req{method: "GET", path: "/admin/pending", cookie: mod}).Body.String()
	for _, want := range []string{
		"3 account(s) waiting, oldest first.", "<caption>Accounts awaiting approval</caption>",
		`<tr><th scope="row">bob</th><td>`,
		`<form method="post" action="/admin/pending/` + id(bob) + `/approve" class="inline">`,
		`Approve<span class="visually-hidden"> bob</span>`,
		`<a href="/admin/pending/` + id(carol) + `/reject">Reject<span class="visually-hidden"> carol</span></a>`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q in:\n%s", want, page)
		}
	}
	if strings.Contains(page, "@") {
		t.Error("the page shows an email address")
	}
	csrf := csrfFrom(t, page)
	post := func(path string, form url.Values) (int, string, string) {
		form.Set("csrf", csrf)
		rec := e.do(req{method: "POST", path: path, cookie: mod, origin: origin, form: form})
		return rec.Code, rec.Header().Get("Location"), rec.Body.String()
	}
	if b := e.do(req{method: "GET", path: "/admin/pending/" + id(carol) + "/reject", cookie: mod}).Body.String(); !strings.Contains(b, "Reject <strong>carol</strong>") {
		t.Errorf("reject confirmation:\n%s", b)
	}

	tests := []struct {
		name     string
		path     string
		form     url.Values
		status   int
		location string
		want     string
	}{
		{"approve", "/admin/pending/" + id(bob) + "/approve", url.Values{}, 303, "/admin/pending?done=approved", ""},
		{"approve again", "/admin/pending/" + id(bob) + "/approve", url.Values{}, 303, "/admin/pending?done=gone", ""},
		{"reject unconfirmed", "/admin/pending/" + id(carol) + "/reject", url.Values{}, 422, "", "Tick the box to confirm"},
		{"reject", "/admin/pending/" + id(carol) + "/reject", url.Values{"confirm": {"yes"}}, 303, "/admin/pending?done=rejected", ""},
		{"reject someone not waiting", "/admin/pending/" + id(e.alice) + "/reject", url.Values{"confirm": {"yes"}}, 303, "/admin/pending?done=gone", ""},
		{"approve an administrator-to-be", "/admin/pending/" + id(boss) + "/approve", url.Values{}, 403, "", errPendingRank},
		{"reject an administrator-to-be", "/admin/pending/" + id(boss) + "/reject", url.Values{"confirm": {"yes"}}, 403, "", errPendingRank},
		{"not a number", "/admin/pending/x/approve", url.Values{}, 303, "/admin/pending?done=gone", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, loc, body := post(tt.path, tt.form)
			if st != tt.status || loc != tt.location || !strings.Contains(body, tt.want) {
				t.Errorf("= %d %q, want %d %q containing %q", st, loc, tt.status, tt.location, tt.want)
			}
		})
	}
	if got := status(bob) + " " + status(carol) + " " + status(boss); got != "active deleted pending" {
		t.Errorf("statuses = %s", got)
	}
	if b := e.do(req{method: "GET", path: "/admin/pending?done=approved", cookie: mod}).Body.String(); !strings.Contains(b, "The account has been approved.") || !strings.Contains(b, "1 account(s) waiting") {
		t.Errorf("after:\n%s", b)
	}
	// The administrator can approve the administrator-to-be.
	admin := e.login(t, e.admin, "admin1")
	adminCSRF := csrfFrom(t, e.do(req{method: "GET", path: "/admin/pending", cookie: admin}).Body.String())
	rec := e.do(req{method: "POST", path: "/admin/pending/" + id(boss) + "/approve", cookie: admin, origin: origin, form: url.Values{"csrf": {adminCSRF}}})
	if rec.Code != 303 || status(boss) != "active" {
		t.Errorf("admin approving = %d, %s", rec.Code, status(boss))
	}
	if b := e.do(req{method: "GET", path: "/admin/pending", cookie: admin}).Body.String(); !strings.Contains(b, "No accounts are waiting for approval.") {
		t.Errorf("empty list:\n%s", b)
	}
}
