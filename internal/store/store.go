// Package store owns the SQLite database: opening it with safe defaults and
// applying schema migrations.
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// CoreOwner is the migration owner name for core (non-plugin) tables.
const CoreOwner = "core"

//go:embed migrations/*.sql
var coreMigrationFS embed.FS

// Per-connection pragmas. They are set through the DSN so every pooled
// connection gets them, not just the first.
var pragmas = []string{
	"foreign_keys(1)",     // enforce FK constraints (off by default in SQLite)
	"journal_mode(WAL)",   // concurrent readers alongside one writer
	"synchronous(NORMAL)", // durable with WAL, far fewer fsyncs than FULL
	"busy_timeout(5000)",  // wait up to 5s for a lock instead of failing at once
	"trusted_schema(0)",   // don't run SQL functions embedded in schema objects
}

// dsn builds a SQLite URI for path. The path is percent-escaped so names
// containing '?', '#' or spaces cannot be misread as URI parameters.
func dsn(path string) string {
	q := url.Values{}
	for _, p := range pragmas {
		q.Add("_pragma", p)
	}
	// Write transactions take the lock up front, avoiding SQLITE_BUSY on
	// read-to-write upgrades under concurrency.
	q.Set("_txlock", "immediate")
	return "file:" + (&url.URL{Path: path}).EscapedPath() + "?" + q.Encode()
}

// Open opens (creating if needed) the database at path, verifies the
// connection, and applies all pending core migrations.
func Open(ctx context.Context, path string, log *slog.Logger) (*sql.DB, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("store: empty database path")
	}
	log = log.With("component", "store")

	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: connect: %w", err)
	}

	var sqliteVersion string
	if err := db.QueryRowContext(ctx, "SELECT sqlite_version()").Scan(&sqliteVersion); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: query version: %w", err)
	}
	log.Info("database opened", "path", path, "sqlite_version", sqliteVersion)

	migs, err := LoadMigrations(coreMigrationFS, "migrations")
	if err != nil {
		db.Close()
		return nil, err
	}
	if err := Migrate(ctx, db, CoreOwner, migs, log); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
