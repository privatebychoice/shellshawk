package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestBrandingPage(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()

	mod := e.login(t, e.mod, "mod1")
	if home := e.do(req{method: "GET", path: "/home", cookie: mod}).Body.String(); strings.Contains(home, "/admin/branding") {
		t.Error("moderator sees the Branding link")
	}
	for _, r := range []req{
		{method: "GET", path: "/admin/branding", cookie: mod},
		{method: "POST", path: "/admin/branding", cookie: mod, origin: origin, form: url.Values{"name": {"Mine"}}},
	} {
		if rec := e.do(r); rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), errSettingsForbidden) {
			t.Errorf("moderator %s = %d", r.method, rec.Code)
		}
	}

	admin := e.login(t, e.admin, "admin1")
	if home := e.do(req{method: "GET", path: "/admin", cookie: admin}).Body.String(); !strings.Contains(home, `<a href="/admin/branding">Branding</a>`) {
		t.Error("admin nav missing the link")
	}
	page := e.do(req{method: "GET", path: "/admin/branding", cookie: admin}).Body.String()
	if !strings.Contains(page, `<input type="text" id="name" name="name" maxlength="40" required autocomplete="off" value="shellshawk" aria-describedby="name-help">`) {
		t.Errorf("form:\n%s", page)
	}
	csrf := csrfFrom(t, page)

	tests := []struct {
		name   string
		form   url.Values
		status int
		want   []string
	}{
		{"wrong CSRF token", url.Values{"csrf": {"x"}, "name": {"Board"}}, http.StatusForbidden, nil},
		{"empty", url.Values{"csrf": {csrf}, "name": {"   "}}, http.StatusUnprocessableEntity, []string{
			`aria-describedby="name-help name-error" aria-invalid="true"`,
			`<p class="error" id="name-error" role="alert">The name must be 1 to 40 printable characters.</p>`,
		}},
		{"escape sequence refused and shown escaped", url.Values{"csrf": {csrf}, "name": {"<b>\x1b[31m"}}, http.StatusUnprocessableEntity, []string{
			`value="&lt;b&gt;`, "The name must be 1 to 40 printable characters.",
		}},
		{"too long", url.Values{"csrf": {csrf}, "name": {strings.Repeat("x", 41)}}, http.StatusUnprocessableEntity, nil},
		{"saved, trimmed", url.Values{"csrf": {csrf}, "name": {"  Example Board "}}, http.StatusSeeOther, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.do(req{method: "POST", path: "/admin/branding", cookie: admin, origin: origin, form: tt.form})
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			for _, w := range tt.want {
				if !strings.Contains(rec.Body.String(), w) {
					t.Errorf("missing %q in:\n%s", w, rec.Body.String())
				}
			}
			if strings.Contains(rec.Body.String(), "<b>") {
				t.Error("typed markup echoed unescaped")
			}
		})
	}
	if got := e.settings.BBSName(ctx); got != "Example Board" {
		t.Errorf("name = %q", got)
	}
	after := e.do(req{method: "GET", path: "/admin/branding?done=saved", cookie: admin}).Body.String()
	if !strings.Contains(after, "The BBS name has been changed.") || !strings.Contains(after, `value="Example Board"`) {
		t.Errorf("after saving:\n%s", after)
	}
}
