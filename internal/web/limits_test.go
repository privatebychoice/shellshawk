package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/settings"
)

func TestConnectionLimitsPage(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()

	// Without core.settings.manage: no link, and the page is refused.
	mod := e.login(t, e.mod, "mod1")
	if home := e.do(req{method: "GET", path: "/home", cookie: mod}).Body.String(); strings.Contains(home, "/admin/limits") {
		t.Error("moderator sees the Connection limits link")
	}
	if rec := e.do(req{method: "GET", path: "/admin/limits", cookie: mod}); rec.Code != http.StatusForbidden {
		t.Errorf("moderator GET = %d", rec.Code)
	}
	if rec := e.do(req{method: "POST", path: "/admin/limits", cookie: mod, origin: origin, form: url.Values{"idle": {"5"}, "max": {"1"}}}); rec.Code != http.StatusForbidden {
		t.Errorf("moderator POST = %d", rec.Code)
	}
	if rec := e.do(req{method: "GET", path: "/admin/limits"}); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("anonymous = %d", rec.Code)
	}

	admin := e.login(t, e.admin, "admin1")
	home := e.do(req{method: "GET", path: "/admin", cookie: admin}).Body.String()
	if !strings.Contains(home, `<a href="/admin/limits">Connection limits</a>`) {
		t.Error("admin nav missing the link")
	}
	page := e.do(req{method: "GET", path: "/admin/limits", cookie: admin}).Body.String()
	for _, want := range []string{
		`<label for="idle">Idle timeout in minutes</label>`,
		`<input type="number" id="idle" name="idle" inputmode="numeric" min="0" max="1440" step="1" required value="30" aria-describedby="idle-help">`,
		`<input type="number" id="max" name="max" inputmode="numeric" min="0" max="20" step="1" required value="3" aria-describedby="max-help">`,
		`id="idle-help">SSH connections with no activity`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q in:\n%s", want, page)
		}
	}
	csrf := csrfFrom(t, page)

	tests := []struct {
		name       string
		form       url.Values
		status     int
		wantInBody []string
	}{
		{"wrong CSRF token", url.Values{"csrf": {"x"}, "idle": {"5"}, "max": {"1"}}, http.StatusForbidden, nil},
		{"both invalid, values kept and escaped", url.Values{"csrf": {csrf}, "idle": {"1"}, "max": {`<x>`}}, http.StatusUnprocessableEntity, []string{
			"The limits were not saved.",
			`value="1" aria-describedby="idle-help idle-error" aria-invalid="true"`,
			`<p class="error" id="idle-error">Idle timeout must be 0 (off) or 2 to 1440 minutes.</p>`,
			`value="&lt;x&gt;" aria-describedby="max-help max-error" aria-invalid="true"`,
			`<p class="error" id="max-error">Enter a whole number.</p>`,
		}},
		{"too many connections", url.Values{"csrf": {csrf}, "idle": {"30"}, "max": {"21"}}, http.StatusUnprocessableEntity, []string{
			"Connections per account must be 0 (no limit) to 20.",
		}},
		{"saved", url.Values{"csrf": {csrf}, "idle": {" 45 "}, "max": {"0"}}, http.StatusSeeOther, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.do(req{method: "POST", path: "/admin/limits", cookie: admin, origin: origin, form: tt.form})
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.status, rec.Body.String())
			}
			for _, w := range tt.wantInBody {
				if !strings.Contains(rec.Body.String(), w) {
					t.Errorf("missing %q in:\n%s", w, rec.Body.String())
				}
			}
			if tt.status == http.StatusSeeOther && rec.Header().Get("Location") != "/admin/limits?done=saved" {
				t.Errorf("redirect = %q", rec.Header().Get("Location"))
			}
		})
	}
	if got := e.settings.ConnLimits(ctx); got != (settings.ConnLimits{IdleMinutes: 45, MaxPerUser: 0}) {
		t.Errorf("limits = %+v", got)
	}
	after := e.do(req{method: "GET", path: "/admin/limits?done=saved", cookie: admin}).Body.String()
	if !strings.Contains(after, `<p class="notice" role="status">Connection limits saved.</p>`) || !strings.Contains(after, `value="45"`) {
		t.Errorf("after saving:\n%s", after)
	}
}
