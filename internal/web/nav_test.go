package web

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/menu"
)

// TestNavFollowsMenu: the navigation is the member menu, with the
// administrators' labels and order, submenus as pages of their own, and
// only what can be opened on the web.
func TestNavFollowsMenu(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	known := testItems{}.ItemExists
	add := func(parent int64, kind, label, target, permission string) string {
		t.Helper()
		id, err := e.menu.Add(ctx, e.admin, menu.Entry{ParentID: parent, Kind: kind, Label: label, Target: target, Permission: permission}, known)
		if err != nil {
			t.Fatal(err)
		}
		return strconv.FormatInt(id, 10)
	}
	num := func(s string) int64 { n, _ := strconv.ParseInt(s, 10, 64); return n }
	// The seeded main menu is Administration, Read notes, Notifications.
	// Rename Read notes and move Notifications above it.
	main, _ := e.menu.Children(ctx, 0)
	if err := e.menu.Update(ctx, e.admin, main[1].ID, "My notes", ""); err != nil {
		t.Fatal(err)
	}
	if err := e.menu.Move(ctx, e.admin, main[2].ID, -1); err != nil {
		t.Fatal(err)
	}
	more := add(0, menu.KindSubmenu, "More", "", "")
	add(num(more), menu.KindItem, "Notes again", "notes:read", "")
	empty := add(0, menu.KindSubmenu, "Empty", "", "")
	secret := add(0, menu.KindSubmenu, "Secret", "", "notes.secret")
	add(num(secret), menu.KindItem, "Secret notes", "notes:read", "")
	deep := add(num(secret), menu.KindSubmenu, "Deep", "", "")
	add(num(deep), menu.KindItem, "Deep notes", "notes:read", "")
	nested := add(0, menu.KindSubmenu, "Nested", "", "")
	inner := add(num(nested), menu.KindSubmenu, "Inner", "", "")
	add(num(inner), menu.KindItem, "Inner notifications", menu.TargetNotifications, "")
	hidden := add(0, menu.KindItem, "Hidden notes", "notes:read", "notes.secret")

	alice, admin := e.login(t, e.alice, "alice"), e.login(t, e.admin, "admin1")
	link := func(href, label string) string { return `<a href="` + href + `">` + label + `</a>` }
	tests := []struct {
		name    string
		as      *http.Cookie
		path    string
		status  int
		want    []string // in this order
		notWant []string
	}{
		{"member's top bar", alice, "/home", http.StatusOK,
			[]string{link("/home", "Home"), link("/notifications", "Notifications"), link("/p/notes/", "My notes"), link("/menu/"+more, "More"), link("/menu/"+nested, "Nested")},
			[]string{"Administration", `href="/admin"`, "Empty", "Secret", "Hidden notes", "Inner", "Read notes"}},
		{"home page does not repeat the links", alice, "/home", http.StatusOK, []string{"Use the links at the top of the page."},
			[]string{`<li><a href="/p/notes/">`}},
		{"administrator's top bar", admin, "/home", http.StatusOK,
			[]string{link("/admin", "Administration"), link("/notifications", "Notifications"), link("/p/notes/", "My notes"), link("/menu/"+more, "More"),
				link("/menu/"+secret, "Secret"), link("/menu/"+nested, "Nested"), link("/p/notes/", "Hidden notes")},
			[]string{"Empty", `href="/admin/users"`}},
		{"a submenu", alice, "/menu/" + more, http.StatusOK,
			[]string{"<title>More", "<h1>More</h1>", `<li><a href="/p/notes/">Notes again</a></li>`, link("/home", "Back to Home")}, nil},
		{"a submenu in a submenu", alice, "/menu/" + inner, http.StatusOK,
			[]string{"<h1>Inner</h1>", `<li><a href="/notifications">Inner notifications</a></li>`, link("/menu/"+nested, "Back to Nested")}, nil},
		{"a submenu that only holds a submenu", alice, "/menu/" + nested, http.StatusOK, []string{`<li><a href="/menu/` + inner + `">Inner</a></li>`}, nil},
		{"a submenu with nothing for the web", alice, "/menu/" + empty, http.StatusNotFound, []string{"That menu does not exist."}, nil},
		{"a submenu behind a permission", alice, "/menu/" + secret, http.StatusNotFound, nil, []string{"Secret notes"}},
		{"under a submenu behind a permission", alice, "/menu/" + deep, http.StatusNotFound, nil, []string{"Deep notes"}},
		{"an item, not a submenu", alice, "/menu/" + hidden, http.StatusNotFound, nil, nil},
		{"no such submenu", alice, "/menu/999", http.StatusNotFound, nil, nil},
		{"not a number", alice, "/menu/x", http.StatusNotFound, nil, nil},
		{"the permission held", admin, "/menu/" + secret, http.StatusOK, []string{"Secret notes", link("/menu/"+deep, "Deep")}, nil},
		{"deep, the permission held", admin, "/menu/" + deep, http.StatusOK, []string{"Deep notes", link("/menu/"+secret, "Back to Secret")}, nil},
		{"Administration", admin, "/admin", http.StatusOK,
			[]string{"<h1>Administration</h1>", link("/admin/users", "Users"), link("/admin/menu", "Menu editor"), link("/home", "Back to Home")}, nil},
		{"Administration, not staff", alice, "/admin", http.StatusForbidden, []string{"You do not have permission to use Administration."}, nil},
		{"anonymous submenu", nil, "/menu/" + more, http.StatusSeeOther, nil, nil},
		{"anonymous Administration", nil, "/admin", http.StatusSeeOther, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.do(req{method: "GET", path: tt.path, cookie: tt.as})
			body := rec.Body.String()
			if rec.Code != tt.status {
				t.Fatalf("= %d, want %d\n%s", rec.Code, tt.status, body)
			}
			at := 0
			for _, w := range tt.want {
				i := strings.Index(body[at:], w)
				if i < 0 {
					t.Errorf("missing %q after position %d\n%s", w, at, body)
					return
				}
				at += i + len(w)
			}
			for _, w := range tt.notWant {
				if strings.Contains(body, w) {
					t.Errorf("shows %q\n%s", w, body)
				}
			}
		})
	}
}
