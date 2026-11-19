package plugin

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// testPlugin is a configurable plugin for tests.
type testPlugin struct {
	m       Manifest
	initErr error
	host    *Host
}

func (p *testPlugin) Manifest() Manifest { return p.m }
func (p *testPlugin) Init(_ context.Context, h *Host) error {
	p.host = h
	return p.initErr
}

func noop(context.Context, Session) error { return nil }

func goodManifest() Manifest {
	return Manifest{
		ID: "notes", Name: "Notes", Version: "1.0.0",
		Permissions: []Permission{
			{Name: "notes.write", Description: "Write notes", DefaultGroups: []string{perm.GroupMember}},
			{Name: "notes.moderate", Description: "Moderate notes"},
		},
		Settings: []Setting{
			{Field: form.Field{Name: "max", Label: "Max notes", Kind: form.SingleLine, Subtype: form.Int, Required: true, Min: form.Bound(1), Max: form.Bound(100)}, Default: "10"},
			{Field: form.Field{Name: "title", Label: "Title", Kind: form.SingleLine, MaxLen: 20}, Default: "Notes"},
		},
		Migrations: []store.Migration{{Version: 1, Name: "notes", SQL: `
			CREATE TABLE notes_items (
				id INTEGER PRIMARY KEY,
				user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
				body TEXT NOT NULL
			) STRICT;
			CREATE INDEX notes_items_user ON notes_items (user_id);`}},
		MenuItems: []MenuItem{{Key: "main", Label: "Notes", AnyOf: []string{"notes.write"}, Run: noop}},
	}
}

type env struct {
	ctx   context.Context
	db    *sql.DB
	deps  Deps
	admin int64
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "p.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ps := perm.NewService(db, perm.NewRegistry(), nil, log)
	for _, q := range []string{
		`INSERT INTO users (id, username, password_hash, status, created_at) VALUES (1, 'a1', 'x', 'active', '2026-01-01T00:00:00Z'), (2, 'm1', 'x', 'active', '2026-01-01T00:00:00Z')`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT 1, id FROM access_groups WHERE name = 'admin'`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT 2, id FROM access_groups WHERE name = 'member'`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return &env{ctx: ctx, db: db, admin: 1, deps: Deps{
		DB: db, Perms: ps, Auth: auth.NewService(db, ps, "new", nil, log), Events: events.New(log), Log: log,
	}}
}

func TestValidate(t *testing.T) {
	mod := func(f func(*Manifest)) Manifest { m := goodManifest(); f(&m); return m }
	page := func(*http.Request, WebSession) (WebPage, error) { return WebPage{}, nil }
	stream := func(http.ResponseWriter, *http.Request, WebSession) error { return nil }
	webRoute := func(r WebRoute) Manifest { return mod(func(m *Manifest) { m.Web = []WebRoute{r} }) }
	notes := func(k ...NotificationKind) Manifest { return mod(func(m *Manifest) { m.Notifications = k }) }
	tests := []struct {
		name string
		m    Manifest
		want string // error substring; "" = valid
	}{
		{"valid", goodManifest(), ""},
		{"bad id", mod(func(m *Manifest) { m.ID = "Notes!" }), "invalid id"},
		{"reserved id", mod(func(m *Manifest) { m.ID = "core" }), "invalid id"},
		{"underscore id", mod(func(m *Manifest) { m.ID = "my_notes" }), "invalid id"},
		{"no version", mod(func(m *Manifest) { m.Version = "" }), "version"},
		{"permission outside namespace", mod(func(m *Manifest) { m.Permissions[0].Name = "core.admin" }), "must start with"},
		{"default group admin", mod(func(m *Manifest) { m.Permissions[0].DefaultGroups = []string{"admin"} }), "admin already"},
		{"invalid setting default", mod(func(m *Manifest) { m.Settings[0].Default = "1000" }), "default for setting"},
		{"duplicate setting", mod(func(m *Manifest) { m.Settings[1].Field.Name = "max" }), "duplicate setting"},
		{"menu item without Run", mod(func(m *Manifest) { m.MenuItems[0].Run = nil }), "needs a label and Run"},
		{"duplicate menu key", mod(func(m *Manifest) { m.MenuItems = append(m.MenuItems, m.MenuItems[0]) }), "duplicate menu item"},
		{"table without prefix", mod(func(m *Manifest) { m.Migrations[0].SQL = "CREATE TABLE items (id INTEGER)" }), `touches "items"`},
		{"drop core table", mod(func(m *Manifest) { m.Migrations[0].SQL = "DROP TABLE IF EXISTS users" }), `touches "users"`},
		{"alter core table", mod(func(m *Manifest) { m.Migrations[0].SQL = "ALTER TABLE users ADD COLUMN x TEXT" }), `touches "users"`},
		{"index on core table", mod(func(m *Manifest) { m.Migrations[0].SQL = "CREATE INDEX notes_x ON users (status)" }), `attaches to "users"`},
		{"trigger on core table", mod(func(m *Manifest) {
			m.Migrations[0].SQL = "CREATE TRIGGER notes_t AFTER DELETE ON users BEGIN SELECT 1; END"
		}), `attaches to "users"`},
		{"sftp mount outside namespace", mod(func(m *Manifest) { m.SFTP = []sftpd.Mount{{Name: "me", FS: nullFS{}}} }), `SFTP mount "me"`},
		{"sftp mount without fs", mod(func(m *Manifest) { m.SFTP = []sftpd.Mount{{Name: "notes"}} }), "no file system"},
		{"sftp mount with id prefix ok", mod(func(m *Manifest) { m.SFTP = []sftpd.Mount{{Name: "notes-archive", FS: nullFS{}}} }), ""},
		{"quoted name checked", mod(func(m *Manifest) { m.Migrations[0].SQL = `CREATE TABLE "users2" (id INTEGER)` }), `touches "users2"`},
		{"web page", webRoute(WebRoute{Path: "/", Handle: page}), ""},
		{"web action", webRoute(WebRoute{Path: "/save", Method: "POST", Handle: page}), ""},
		{"web stream", webRoute(WebRoute{Path: "/live", Stream: stream}), ""},
		{"web route without handler", webRoute(WebRoute{Path: "/"}), "invalid web route"},
		{"web route with both handlers", webRoute(WebRoute{Path: "/", Handle: page, Stream: stream}), "invalid web route"},
		{"web stream by POST", webRoute(WebRoute{Path: "/live", Method: "POST", Stream: stream}), "invalid web route"},
		{"web route other method", webRoute(WebRoute{Path: "/", Method: "DELETE", Handle: page}), "invalid web route"},
		{"web route relative path", webRoute(WebRoute{Path: "x", Handle: page}), "invalid web route"},
		{"notification kind", notes(NotificationKind{Key: "due", Label: "Due notes"}), ""},
		{"notification kind without label", notes(NotificationKind{Key: "due"}), "invalid or duplicate notification kind"},
		{"notification kind bad key", notes(NotificationKind{Key: "Due!", Label: "Due"}), "invalid or duplicate notification kind"},
		{"duplicate notification kind", notes(NotificationKind{Key: "due", Label: "A"}, NotificationKind{Key: "due", Label: "B"}), "invalid or duplicate notification kind"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.m)
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	e := newEnv(t)
	p := &testPlugin{m: goodManifest()}
	r, err := Load(e.ctx, e.deps, p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Migrations ran under the plugin's own owner.
	var n int
	e.db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE owner = 'notes'`).Scan(&n)
	if n != 1 {
		t.Errorf("plugin migrations recorded = %d", n)
	}
	if _, err := e.db.Exec(`INSERT INTO notes_items (user_id, body) VALUES (2, 'hi')`); err != nil {
		t.Errorf("plugin table missing: %v", err)
	}
	// Permissions registered and default grant applied.
	if !e.deps.Perms.Registry().Known("notes.moderate") {
		t.Error("permission not registered")
	}
	if ok, _ := e.deps.Perms.Has(e.ctx, 2, "notes.write"); !ok {
		t.Error("default group grant not applied")
	}
	// Host is scoped to the plugin.
	if p.host == nil || p.host.ID != "notes" || p.host.Settings.id != "notes" {
		t.Errorf("host = %+v", p.host)
	}
	it, ok := r.Item("notes:main")
	if !ok || it.PluginID != "notes" || len(r.Items()) != 1 || len(r.Plugins()) != 1 {
		t.Errorf("items = %+v", r.Items())
	}
	if it.Allowed(perm.Set{}) || !it.Allowed(perm.Set{"notes.write": true}) || !it.Allowed(perm.Set{perm.Admin: true}) {
		t.Error("Allowed() wrong")
	}
}

func TestGrantsSeededOnce(t *testing.T) {
	e := newEnv(t)
	if _, err := Load(e.ctx, e.deps, &testPlugin{m: goodManifest()}); err != nil {
		t.Fatal(err)
	}
	// An administrator revokes the default grant...
	g, _ := e.deps.Perms.GroupByName(e.ctx, perm.GroupMember)
	if err := e.deps.Perms.Revoke(e.ctx, e.admin, g.ID, "notes.write"); err != nil {
		t.Fatal(err)
	}
	// ...and a restart (fresh permission registry, same database) must not
	// grant it again.
	e.deps.Perms = perm.NewService(e.db, perm.NewRegistry(), nil, e.deps.Log)
	if _, err := Load(e.ctx, e.deps, &testPlugin{m: goodManifest()}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := e.deps.Perms.Has(e.ctx, 2, "notes.write"); ok {
		t.Error("revoked default permission was granted again on restart")
	}
}

func TestLoadFailures(t *testing.T) {
	second := goodManifest()
	tests := []struct {
		name    string
		plugins []Plugin
		want    string
	}{
		{"duplicate id", []Plugin{&testPlugin{m: goodManifest()}, &testPlugin{m: second}}, "duplicate"},
		{"init error", []Plugin{&testPlugin{m: goodManifest(), initErr: errors.New("no config")}}, "init: no config"},
		{"broken migration", []Plugin{&testPlugin{m: func() Manifest {
			m := goodManifest()
			m.Migrations[0].SQL = "CREATE TABLE notes_x (id INTEGER) STRICT; NOT SQL;"
			return m
		}()}}, "notes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEnv(t)
			if _, err := Load(e.ctx, e.deps, tt.plugins...); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestSettings(t *testing.T) {
	e := newEnv(t)
	r, err := Load(e.ctx, e.deps, &testPlugin{m: goodManifest()})
	if err != nil {
		t.Fatal(err)
	}
	st := r.Plugins()[0].Settings

	vals, err := st.All(e.ctx)
	if err != nil || vals["max"] != "10" || vals["title"] != "Notes" {
		t.Fatalf("defaults = %v, %v", vals, err)
	}
	ferrs, err := st.Save(e.ctx, e.admin, form.Values{"max": "500", "title": "x"})
	if err != nil || ferrs["max"] == nil {
		t.Errorf("invalid value accepted: %v %v", ferrs, err)
	}
	if _, err := st.Save(e.ctx, 2, form.Values{"max": "5", "title": "x"}); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member saving settings err = %v", err)
	}
	if ferrs, err := st.Save(e.ctx, e.admin, form.Values{"max": " 25 ", "title": "Board notes"}); err != nil || ferrs != nil {
		t.Fatalf("Save: %v %v", ferrs, err)
	}
	if v, _ := st.Get(e.ctx, "max"); v != "25" {
		t.Errorf("max = %q", v)
	}
	if _, err := st.Get(e.ctx, "nope"); err == nil {
		t.Error("unknown key accepted")
	}
	// A stored value that no longer validates falls back to the default.
	e.db.Exec(`UPDATE plugin_settings SET value = 'junk' WHERE key = 'max'`)
	if v, _ := st.Get(e.ctx, "max"); v != "10" {
		t.Errorf("invalid stored value = %q, want default", v)
	}
	var audits int
	e.db.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'plugin.setting.changed'`).Scan(&audits)
	if audits != 1 {
		t.Errorf("audit entries = %d", audits)
	}
}

type nullFS struct{}

func (nullFS) List(context.Context, sftpd.User, []string) ([]sftpd.Entry, error) { return nil, nil }
func (nullFS) Read(context.Context, sftpd.User, []string) ([]byte, time.Time, error) {
	return nil, time.Time{}, sftpd.ErrNotExist
}
