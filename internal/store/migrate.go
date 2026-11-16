package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"regexp"
	"slices"
	"strconv"
	"time"
)

// Migration is one forward-only schema change. Core and every plugin keep
// independent version sequences, distinguished by owner.
type Migration struct {
	Version int    // strictly increasing, starting at 1
	Name    string // short description, e.g. "system_settings"
	SQL     string // one or more statements, applied in a single transaction
}

func (m Migration) checksum() string {
	sum := sha256.Sum256([]byte(m.SQL))
	return hex.EncodeToString(sum[:])
}

const migrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
	owner      TEXT    NOT NULL,
	version    INTEGER NOT NULL,
	name       TEXT    NOT NULL,
	checksum   TEXT    NOT NULL,
	applied_at TEXT    NOT NULL,
	PRIMARY KEY (owner, version)
) STRICT`

var migrationFile = regexp.MustCompile(`^(\d{4})_([a-z0-9_]+)\.sql$`)

// LoadMigrations reads files named NNNN_name.sql from dir in fsys. Any other
// file in dir is an error, so a misnamed migration can't be silently skipped.
func LoadMigrations(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("store: read migrations: %w", err)
	}
	var migs []Migration
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := migrationFile.FindStringSubmatch(e.Name())
		if m == nil {
			return nil, fmt.Errorf("store: migration file %q does not match NNNN_name.sql", e.Name())
		}
		v, _ := strconv.Atoi(m[1]) // regexp guarantees digits
		b, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("store: read migration %q: %w", e.Name(), err)
		}
		migs = append(migs, Migration{Version: v, Name: m[2], SQL: string(b)})
	}
	slices.SortFunc(migs, func(a, b Migration) int { return a.Version - b.Version })
	return migs, nil
}

func validate(owner string, migs []Migration) error {
	if owner == "" {
		return fmt.Errorf("store: migration owner is empty")
	}
	for i, m := range migs {
		if m.Version != i+1 {
			return fmt.Errorf("store: %s migrations must be numbered 1..n without gaps; position %d has version %d", owner, i+1, m.Version)
		}
		if m.SQL == "" {
			return fmt.Errorf("store: %s migration %d (%s) is empty", owner, m.Version, m.Name)
		}
	}
	return nil
}

// Migrate applies every migration in migs that owner has not yet applied.
// Each migration runs in its own transaction together with its bookkeeping
// row, so a failure leaves the schema at the last good version.
//
// It refuses to run if the database records a version this binary doesn't
// know (the binary is older than the database) or if an applied migration's
// SQL has since been edited (checksum mismatch).
func Migrate(ctx context.Context, db *sql.DB, owner string, migs []Migration, log *slog.Logger) error {
	if err := validate(owner, migs); err != nil {
		return err
	}
	if _, err := db.ExecContext(ctx, migrationsTable); err != nil {
		return fmt.Errorf("store: create schema_migrations: %w", err)
	}

	applied, err := appliedChecksums(ctx, db, owner)
	if err != nil {
		return err
	}
	for v, sum := range applied {
		if v < 1 {
			return fmt.Errorf("store: database records invalid %s migration version %d", owner, v)
		}
		if v > len(migs) {
			return fmt.Errorf("store: database has %s migration %d but this build only knows %d; refusing to run an older binary", owner, v, len(migs))
		}
		if want := migs[v-1].checksum(); sum != want {
			return fmt.Errorf("store: %s migration %d (%s) was modified after being applied", owner, v, migs[v-1].Name)
		}
	}

	pending := 0
	for _, m := range migs {
		if _, ok := applied[m.Version]; ok {
			continue
		}
		pending++
		log.Info("applying migration", "owner", owner, "version", m.Version, "name", m.Name)
		if err := apply(ctx, db, owner, m); err != nil {
			log.Error("migration failed", "owner", owner, "version", m.Version, "name", m.Name, "err", err)
			return err
		}
	}
	log.Info("schema up to date", "owner", owner, "version", len(migs), "applied_now", pending)
	return nil
}

func appliedChecksums(ctx context.Context, db *sql.DB, owner string) (map[int]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT version, checksum FROM schema_migrations WHERE owner = ?`, owner)
	if err != nil {
		return nil, fmt.Errorf("store: read applied migrations: %w", err)
	}
	defer rows.Close()
	out := map[int]string{}
	for rows.Next() {
		var v int
		var sum string
		if err := rows.Scan(&v, &sum); err != nil {
			return nil, fmt.Errorf("store: scan applied migration: %w", err)
		}
		out[v] = sum
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read applied migrations: %w", err)
	}
	return out, nil
}

func apply(ctx context.Context, db *sql.DB, owner string, m Migration) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin %s migration %d: %w", owner, m.Version, err)
	}
	defer tx.Rollback() // no-op after Commit

	if _, err := tx.ExecContext(ctx, m.SQL); err != nil {
		return fmt.Errorf("store: %s migration %d (%s): %w", owner, m.Version, m.Name, err)
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_migrations (owner, version, name, checksum, applied_at) VALUES (?, ?, ?, ?, ?)`,
		owner, m.Version, m.Name, m.checksum(), time.Now().UTC().Format(time.RFC3339),
	); err != nil {
		return fmt.Errorf("store: record %s migration %d: %w", owner, m.Version, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit %s migration %d: %w", owner, m.Version, err)
	}
	return nil
}
