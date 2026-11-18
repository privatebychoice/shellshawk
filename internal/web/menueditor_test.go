package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/menu"
)

func TestMenuEditor(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	entries := func(parent int64) []menu.Entry {
		t.Helper()
		es, err := e.menu.Children(ctx, parent)
		if err != nil {
			t.Fatal(err)
		}
		return es
	}
	labels := func(parent int64) string {
		var out []string
		for _, en := range entries(parent) {
			out = append(out, en.Label)
		}
		return strings.Join(out, ", ")
	}
	id := func(n int64) string { return strconv.FormatInt(n, 10) }

	// Without core.menu.manage: no link, pages refused.
	mod := e.login(t, e.mod, "mod1")
	if home := e.do(req{method: "GET", path: "/home", cookie: mod}).Body.String(); strings.Contains(home, "/admin/menu") {
		t.Error("moderator sees the Menu editor link")
	}
	if rec := e.do(req{method: "GET", path: "/admin/menu", cookie: mod}); rec.Code != http.StatusForbidden {
		t.Errorf("moderator = %d", rec.Code)
	}

	admin := e.login(t, e.admin, "admin1")
	if home := e.do(req{method: "GET", path: "/home", cookie: admin}).Body.String(); !strings.Contains(home, `<a href="/admin/menu">Menu editor</a>`) {
		t.Error("admin nav missing the link")
	}
	page := e.do(req{method: "GET", path: "/admin/menu", cookie: admin}).Body.String()
	adminEntry, notesEntry := entries(0)[0], entries(0)[1]
	for _, want := range []string{
		"<caption>Entries in the main menu, in order</caption>",
		`<tr id="entry-` + id(adminEntry.ID) + `"><td>1</td><th scope="row">Administration</th><td>core:admin</td><td>none</td>`,
		`<button type="submit" name="direction" value="down">Move down<span class="visually-hidden"> Administration</span></button>`,
		`<option value="notes:read">Read notes (notes:read)</option>`,
		`<option value="notes.secret">notes.secret: secret</option>`,
		"Reset to the default menu",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(page, `value="up">Move up<span class="visually-hidden"> Administration`) {
		t.Error("the first entry offers Move up")
	}
	if t.Failed() {
		t.Logf("page:\n%s", page)
	}
	csrf := csrfFrom(t, page)
	post := func(path string, form url.Values) (int, string, string) {
		form.Set("csrf", csrf)
		rec := e.do(req{method: "POST", path: path, cookie: admin, origin: origin, form: form})
		return rec.Code, rec.Header().Get("Location"), rec.Body.String()
	}

	// Adding.
	addTests := []struct {
		name     string
		form     url.Values
		status   int
		location string
		want     string
	}{
		{"item without a target", url.Values{"kind": {"item"}}, 422, "", `<p class="error" id="add-target-error">Choose the menu item.</p>`},
		{"submenu without a label", url.Values{"kind": {"submenu"}, "label": {"  "}}, 422, "", "A submenu needs a label."},
		{"label with an escape sequence", url.Values{"kind": {"submenu"}, "label": {"More\x1b[31m"}}, 422, "", `<p class="error" id="add-label-error">Label must be 1 to 40 printable characters.</p>`},
		{"unknown permission", url.Values{"kind": {"submenu"}, "label": {"More"}, "perm": {"no.such"}}, 422, "", "Unknown permission &#34;no.such&#34;."},
		{"submenu", url.Values{"kind": {"submenu"}, "label": {"More"}}, 303, "/admin/menu?done=added", ""},
	}
	for _, tt := range addTests {
		t.Run("add: "+tt.name, func(t *testing.T) {
			status, loc, body := post("/admin/menu/add", tt.form)
			if status != tt.status || loc != tt.location || !strings.Contains(body, tt.want) {
				t.Errorf("= %d %q, want %d %q containing %q:\n%s", status, loc, tt.status, tt.location, tt.want, body)
			}
		})
	}
	more := entries(0)[2]
	// An item in the submenu, named after the item when the label is empty.
	if status, loc, _ := post("/admin/menu/add", url.Values{"kind": {"item"}, "target": {"notes:read"}, "parent": {id(more.ID)}}); status != 303 || loc != "/admin/menu?parent="+id(more.ID)+"&done=added" {
		t.Fatalf("add to submenu = %d %q", status, loc)
	}
	if got := labels(more.ID); got != "Read notes" {
		t.Errorf("submenu = %q", got)
	}
	sub := e.do(req{method: "GET", path: "/admin/menu?parent=" + id(more.ID), cookie: admin}).Body.String()
	if !strings.Contains(sub, "<caption>Entries in the submenu More, in order</caption>") || !strings.Contains(sub, `<a href="/admin/menu">Back to the main menu</a>`) ||
		strings.Contains(sub, "Reset to the default menu") {
		t.Errorf("submenu page:\n%s", sub)
	}
	for _, p := range []string{"/admin/menu?parent=999", "/admin/menu?parent=" + id(notesEntry.ID), "/admin/menu/999"} {
		if rec := e.do(req{method: "GET", path: p, cookie: admin}); rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", p, rec.Code)
		}
	}

	// Moving.
	if status, loc, _ := post("/admin/menu/"+id(more.ID)+"/move", url.Values{"direction": {"up"}}); status != 303 || loc != "/admin/menu?done=moved#entry-"+id(more.ID) {
		t.Errorf("move = %d %q", status, loc)
	}
	if got := labels(0); got != "Administration, More, Read notes" {
		t.Errorf("after moving up: %q", got)
	}
	if status, _, _ := post("/admin/menu/"+id(more.ID)+"/move", url.Values{"direction": {"sideways"}}); status != http.StatusBadRequest {
		t.Errorf("bad direction = %d", status)
	}

	// Editing.
	edit := e.do(req{method: "GET", path: "/admin/menu/" + id(adminEntry.ID), cookie: admin}).Body.String()
	if !strings.Contains(edit, "Administration cannot be deleted") || strings.Contains(edit, "/delete") {
		t.Errorf("Administration edit page offers deleting:\n%s", edit)
	}
	if status, _, body := post("/admin/menu/"+id(adminEntry.ID), url.Values{"label": {""}}); status != 422 || !strings.Contains(body, `<p class="error" id="label-error">Label must be 1 to 40 printable characters.</p>`) {
		t.Errorf("empty label = %d:\n%s", status, body)
	}
	if status, loc, _ := post("/admin/menu/"+id(adminEntry.ID), url.Values{"label": {"Admin"}, "perm": {"notes.secret"}}); status != 303 || loc != "/admin/menu?done=saved" {
		t.Errorf("save = %d %q", status, loc)
	}
	if got, _ := e.menu.Get(ctx, adminEntry.ID); got.Label != "Admin" || got.Permission != "notes.secret" {
		t.Errorf("saved entry = %+v", got)
	}

	// Deleting.
	delTests := []struct {
		name   string
		entry  int64
		form   url.Values
		status int
		want   string
	}{
		{"not confirmed", notesEntry.ID, url.Values{}, 422, "Tick the box to confirm"},
		{"Administration", adminEntry.ID, url.Values{"confirm": {"yes"}}, 422, "Administration cannot be deleted"},
		{"submenu with entries", more.ID, url.Values{"confirm": {"yes"}}, 422, "Remove the entries in this submenu first."},
		{"item", notesEntry.ID, url.Values{"confirm": {"yes"}}, 303, ""},
	}
	for _, tt := range delTests {
		t.Run("delete: "+tt.name, func(t *testing.T) {
			status, _, body := post("/admin/menu/"+id(tt.entry)+"/delete", tt.form)
			if status != tt.status || !strings.Contains(body, tt.want) {
				t.Errorf("= %d, want %d containing %q", status, tt.status, tt.want)
			}
		})
	}
	if got := labels(0); got != "Admin, More" {
		t.Errorf("after deleting: %q", got)
	}

	// Reset.
	if status, _, body := post("/admin/menu/reset", url.Values{}); status != 422 || !strings.Contains(body, "Tick the box to confirm the reset") {
		t.Errorf("reset unconfirmed = %d", status)
	}
	if status, loc, _ := post("/admin/menu/reset", url.Values{"confirm": {"yes"}}); status != 303 || loc != "/admin/menu?done=reset" {
		t.Errorf("reset = %d %q", status, loc)
	}
	if got := labels(0); got != "Administration, Read notes" {
		t.Errorf("after reset: %q", got)
	}
	if b := e.do(req{method: "GET", path: "/admin/menu?done=reset", cookie: admin}).Body.String(); !strings.Contains(b, "The default menu has been restored.") {
		t.Error("reset notice missing")
	}

	// A wrong token changes nothing.
	rec := e.do(req{method: "POST", path: "/admin/menu/reset", cookie: admin, origin: origin, form: url.Values{"csrf": {"x"}, "confirm": {"yes"}}})
	if rec.Code != http.StatusForbidden {
		t.Errorf("wrong token = %d", rec.Code)
	}
}
