package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/form"
)

func TestPluginSettingsPages(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	notes := e.srv.cfg.Plugins.Plugins()[0].Settings

	// Members without core.plugins.settings: no link, pages refused.
	alice := e.login(t, e.alice, "alice")
	if home := e.do(req{method: "GET", path: "/home", cookie: alice}).Body.String(); strings.Contains(home, "/admin/plugins") {
		t.Error("member sees the Plugin settings link")
	}
	for _, r := range []req{
		{method: "GET", path: "/admin/plugins", cookie: alice},
		{method: "GET", path: "/admin/plugins/notes", cookie: alice},
		{method: "POST", path: "/admin/plugins/notes", cookie: alice, origin: origin, form: url.Values{"f-max": {"5"}}},
	} {
		if rec := e.do(r); rec.Code != http.StatusForbidden {
			t.Errorf("member %s %s = %d", r.method, r.path, rec.Code)
		}
	}

	// Moderators hold the permission by default.
	mod := e.login(t, e.mod, "mod1")
	if home := e.do(req{method: "GET", path: "/home", cookie: mod}).Body.String(); !strings.Contains(home, `<a href="/admin/plugins">Plugin settings</a>`) {
		t.Error("moderator nav missing the link")
	}
	if list := e.do(req{method: "GET", path: "/admin/plugins", cookie: mod}).Body.String(); !strings.Contains(list, `<a href="/admin/plugins/notes">Notes</a>`) {
		t.Errorf("list:\n%s", list)
	}
	if rec := e.do(req{method: "GET", path: "/admin/plugins/nope", cookie: mod}); rec.Code != http.StatusNotFound {
		t.Errorf("unknown plugin = %d", rec.Code)
	}

	page := e.do(req{method: "GET", path: "/admin/plugins/notes", cookie: mod}).Body.String()
	for _, want := range []string{
		`<label for="f-max">Most notes</label>`,
		`<input type="number" id="f-max" name="f-max" inputmode="numeric" step="1" min="1" max="50" required value="10" aria-describedby="f-max-rules f-max-help">`,
		`<span class="meta" id="f-max-rules">whole number, 1 to 50, required</span>`,
		`<span class="meta" id="f-max-help">Per member.</span>`,
		`<input type="text" id="f-title" name="f-title" maxlength="20" value="Notes" aria-describedby="f-title-rules">`,
		`<textarea id="f-csrf" name="f-csrf" rows="6" maxlength="200" aria-describedby="f-csrf-rules"></textarea>`,
		`<input type="checkbox" id="f-public" name="f-public" value="true" checked aria-describedby="f-public-rules">`,
		`<select id="f-sort" name="f-sort" required aria-describedby="f-sort-rules">`,
		`<option value="new" selected>Newest first</option>`,
		`<fieldset aria-describedby="f-tags-rules">`, `<legend>Tags</legend>`,
		`<input type="checkbox" name="f-tags" value="a" checked> Alpha`,
		`<input type="checkbox" name="f-tags" value="b"> Beta`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q", want)
		}
	}
	if t.Failed() {
		t.Logf("page:\n%s", page)
	}
	csrf := csrfFrom(t, page)
	post := func(form url.Values) *httpResult {
		form.Set("csrf", csrf)
		rec := e.do(req{method: "POST", path: "/admin/plugins/notes", cookie: mod, origin: origin, form: form})
		return &httpResult{rec.Code, rec.Header().Get("Location"), rec.Body.String()}
	}

	// Invalid: errors at their fields, values kept (escaped).
	bad := post(url.Values{"f-max": {"99"}, "f-title": {strings.Repeat("x", 21)}, "f-csrf": {"<b>hi</b>"}, "f-sort": {"new"}})
	for _, want := range []string{
		"The settings were not saved.",
		`value="99" aria-describedby="f-max-rules f-max-help f-max-error" aria-invalid="true"`,
		`<p class="error" id="f-max-error">Most notes must be at most 50.</p>`,
		`<p class="error" id="f-title-error">Title must be at most 20 characters.</p>`,
		`&lt;b&gt;hi&lt;/b&gt;</textarea>`,
	} {
		if bad.status != http.StatusUnprocessableEntity || !strings.Contains(bad.body, want) {
			t.Errorf("invalid save (%d) missing %q", bad.status, want)
		}
	}

	// Valid: an unticked box is false, several choices are joined, and a
	// setting called "csrf" does not clash with the form's token.
	ok := post(url.Values{"f-max": {"5"}, "f-title": {"Mine"}, "f-csrf": {"footer text"}, "f-sort": {"old"}, "f-tags": {"a", "b"}})
	if ok.status != http.StatusSeeOther || ok.location != "/admin/plugins/notes?done=saved" {
		t.Fatalf("save = %d %q: %s", ok.status, ok.location, ok.body)
	}
	got, _ := notes.All(ctx)
	want := form.Values{"max": "5", "title": "Mine", "csrf": "footer text", "public": form.False, "sort": "old", "tags": "a,b"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	after := e.do(req{method: "GET", path: "/admin/plugins/notes?done=saved", cookie: mod}).Body.String()
	if !strings.Contains(after, `<p class="notice" role="status">Settings saved.</p>`) || strings.Contains(after, `name="f-public" value="true" checked`) {
		t.Errorf("after saving:\n%s", after)
	}

	// Wrong token.
	if rec := e.do(req{method: "POST", path: "/admin/plugins/notes", cookie: mod, origin: origin, form: url.Values{"csrf": {"x"}, "f-max": {"5"}}}); rec.Code != http.StatusForbidden {
		t.Errorf("wrong token = %d", rec.Code)
	}
}

type httpResult struct {
	status         int
	location, body string
}
