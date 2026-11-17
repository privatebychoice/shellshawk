package store

import (
	"context"
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func openTemp(t *testing.T, name string) *sql.DB {
	t.Helper()
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), name), discard())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestOpenAppliesCoreMigrationsAndPragmas(t *testing.T) {
	// Space and '?' in the name check the DSN escaping.
	db := openTemp(t, "bbs data?.db")
	ctx := context.Background()

	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE owner = ?`, CoreOwner).Scan(&n); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if n < 1 {
		t.Fatalf("core migrations applied = %d, want >= 1", n)
	}
	if _, err := db.ExecContext(ctx, `SELECT key FROM system_settings`); err != nil {
		t.Errorf("system_settings missing: %v", err)
	}

	pragmaWant := map[string]string{"foreign_keys": "1", "journal_mode": "wal", "busy_timeout": "5000", "trusted_schema": "0"}
	for p, want := range pragmaWant {
		var got string
		if err := db.QueryRowContext(ctx, "PRAGMA "+p).Scan(&got); err != nil {
			t.Fatalf("PRAGMA %s: %v", p, err)
		}
		if got != want {
			t.Errorf("PRAGMA %s = %q, want %q", p, got, want)
		}
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bbs.db")
	for i := range 2 {
		db, err := Open(context.Background(), path, discard())
		if err != nil {
			t.Fatalf("Open #%d: %v", i+1, err)
		}
		db.Close()
	}
}

func TestOpenEmptyPath(t *testing.T) {
	if _, err := Open(context.Background(), "  ", discard()); err == nil {
		t.Fatal("Open(\"  \") error = nil, want error")
	}
}

func TestMigrate(t *testing.T) {
	m1 := Migration{Version: 1, Name: "a", SQL: "CREATE TABLE a (id INTEGER PRIMARY KEY) STRICT;"}
	m2 := Migration{Version: 2, Name: "b", SQL: "CREATE TABLE b (id INTEGER PRIMARY KEY) STRICT;"}
	bad := Migration{Version: 2, Name: "bad", SQL: "CREATE TABLE b (id INTEGER PRIMARY KEY) STRICT; SYNTAX ERROR;"}

	tests := []struct {
		name    string
		before  []Migration // applied first, must succeed
		owner   string
		migs    []Migration
		wantErr string
		wantVer int // highest version recorded for owner afterwards
	}{
		{name: "fresh", owner: "p", migs: []Migration{m1, m2}, wantVer: 2},
		{name: "incremental", before: []Migration{m1}, owner: "p", migs: []Migration{m1, m2}, wantVer: 2},
		{name: "nothing pending", before: []Migration{m1, m2}, owner: "p", migs: []Migration{m1, m2}, wantVer: 2},
		{name: "empty list", owner: "p", migs: nil, wantVer: 0},
		{name: "gap", owner: "p", migs: []Migration{m2}, wantErr: "without gaps"},
		{name: "empty owner", owner: "", migs: []Migration{m1}, wantErr: "owner is empty"},
		{name: "empty sql", owner: "p", migs: []Migration{{Version: 1, Name: "x"}}, wantErr: "is empty"},
		{name: "older binary", before: []Migration{m1, m2}, owner: "p", migs: []Migration{m1}, wantErr: "older binary", wantVer: 2},
		{
			name: "edited after apply", before: []Migration{m1}, owner: "p",
			migs:    []Migration{{Version: 1, Name: "a", SQL: m1.SQL + " -- changed"}},
			wantErr: "modified", wantVer: 1,
		},
		{name: "failure rolls back", before: []Migration{m1}, owner: "p", migs: []Migration{m1, bad}, wantErr: "migration 2", wantVer: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			db := openTemp(t, "m.db")
			if tt.before != nil {
				if err := Migrate(ctx, db, "p", tt.before, discard()); err != nil {
					t.Fatalf("setup Migrate: %v", err)
				}
			}
			err := Migrate(ctx, db, tt.owner, tt.migs, discard())
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Migrate() error = %v, want containing %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Migrate() unexpected error: %v", err)
			}
			if tt.owner == "" {
				return
			}
			var ver sql.NullInt64
			if err := db.QueryRowContext(ctx, `SELECT max(version) FROM schema_migrations WHERE owner = ?`, tt.owner).Scan(&ver); err != nil {
				t.Fatalf("read version: %v", err)
			}
			if int(ver.Int64) != tt.wantVer {
				t.Errorf("recorded version = %d, want %d", ver.Int64, tt.wantVer)
			}
		})
	}
}

func TestMigrateFailureLeavesNoPartialSchema(t *testing.T) {
	ctx := context.Background()
	db := openTemp(t, "m.db")
	bad := Migration{Version: 1, Name: "bad", SQL: "CREATE TABLE half (id INTEGER) STRICT; SYNTAX ERROR;"}
	if err := Migrate(ctx, db, "p", []Migration{bad}, discard()); err == nil {
		t.Fatal("Migrate() error = nil, want error")
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE name = 'half'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Error("table from failed migration was left behind")
	}
}

func TestLoadMigrations(t *testing.T) {
	tests := []struct {
		name    string
		fs      fstest.MapFS
		want    []string // names in order
		wantErr bool
	}{
		{
			name: "sorted by version",
			fs: fstest.MapFS{
				"m/0002_second.sql": {Data: []byte("SELECT 2;")},
				"m/0001_first.sql":  {Data: []byte("SELECT 1;")},
			},
			want: []string{"first", "second"},
		},
		{name: "bad name", fs: fstest.MapFS{"m/1_x.sql": {Data: []byte("x")}}, wantErr: true},
		{name: "stray file", fs: fstest.MapFS{"m/README.md": {Data: []byte("x")}}, wantErr: true},
		{name: "missing dir", fs: fstest.MapFS{}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			migs, err := LoadMigrations(tt.fs, "m")
			if (err != nil) != tt.wantErr {
				t.Fatalf("LoadMigrations() error = %v, wantErr %v", err, tt.wantErr)
			}
			var got []string
			for _, m := range migs {
				got = append(got, m.Name)
			}
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Errorf("names = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestLogoutEntryRemoved upgrades a database from before migration 7: the
// Log out menu entry goes (q logs out instead), wherever it was moved,
// other entries stay, and it stays marked as seeded so it is not re-added.
func TestLogoutEntryRemoved(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", dsn(filepath.Join(t.TempDir(), "up.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	migs, err := LoadMigrations(coreMigrationFS, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db, CoreOwner, migs[:6], discard()); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO menu_entries (id, parent_id, position, label, kind, target, created_at) VALUES
			(1, NULL, 1, 'Administration', 'item', 'core:admin', '2026-01-01T00:00:00Z'),
			(2, NULL, 2, 'Log out', 'item', 'core:logout', '2026-01-01T00:00:00Z'),
			(3, NULL, 3, 'More', 'submenu', '', '2026-01-01T00:00:00Z'),
			(4, 3, 1, 'Bye', 'item', 'core:logout', '2026-01-01T00:00:00Z')`,
		`INSERT INTO menu_seeded (target) VALUES ('core:admin'), ('core:logout')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(ctx, db, CoreOwner, migs, discard()); err != nil {
		t.Fatal(err)
	}
	var entries, logouts, seeded int
	db.QueryRowContext(ctx, `SELECT count(*), count(*) FILTER (WHERE target = 'core:logout') FROM menu_entries`).Scan(&entries, &logouts)
	db.QueryRowContext(ctx, `SELECT count(*) FROM menu_seeded WHERE target = 'core:logout'`).Scan(&seeded)
	if entries != 2 || logouts != 0 || seeded != 1 {
		t.Errorf("entries = %d, logout entries = %d, logout seeded = %d; want 2, 0, 1", entries, logouts, seeded)
	}
}
