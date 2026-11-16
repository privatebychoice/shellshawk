// Package settings stores system-wide settings (branding and similar) in the
// system_settings table. Changes require core.settings.manage and are
// audited.
package settings

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Known settings.
const (
	KeyBBSName = "branding.name"
)

// DefaultBBSName is used until an administrator sets one.
const DefaultBBSName = "shellshawk"

// MaxBBSNameLen bounds the name shown in every title bar.
const MaxBBSNameLen = 40

// ErrInvalid is returned for an unacceptable value.
var ErrInvalid = errors.New("invalid setting value")

// Service reads and writes settings.
type Service struct {
	db  *sql.DB
	now func() time.Time
	log *slog.Logger
}

// NewService returns a Service. now may be nil.
func NewService(db *sql.DB, now func() time.Time, log *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, now: now, log: log.With("component", "settings")}
}

// get returns the stored value for key, or def if unset.
func (s *Service) get(ctx context.Context, key, def string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM system_settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return def, nil
	}
	if err != nil {
		return "", fmt.Errorf("settings: get %s: %w", key, err)
	}
	return v, nil
}

func (s *Service) set(ctx context.Context, actor int64, key, value string) error {
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := perm.RequireTx(ctx, tx, actor, perm.SettingsManage); err != nil {
			return err
		}
		now := s.now()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
			key, value, store.FormatTime(now)); err != nil {
			return fmt.Errorf("settings: set %s: %w", key, err)
		}
		s.log.Info("setting changed", "actor", actor, "key", key)
		return audit.Record(ctx, tx, now, audit.Entry{Actor: actor, Action: audit.SettingChanged, TargetType: "setting", Detail: key})
	})
}

// BBSName returns the BBS name, falling back to the default on error so a
// database problem never blanks every title bar.
func (s *Service) BBSName(ctx context.Context) string {
	v, err := s.get(ctx, KeyBBSName, DefaultBBSName)
	if err != nil {
		s.log.Error("read BBS name", "err", err)
		return DefaultBBSName
	}
	return v
}

// NormalizeBBSName trims and validates a BBS name: 1 to MaxBBSNameLen
// printable characters.
func NormalizeBBSName(name string) (string, error) {
	name = strings.TrimSpace(name)
	n := utf8.RuneCountInString(name)
	if n == 0 || n > MaxBBSNameLen || term.Sanitize(name, false) != name {
		return "", fmt.Errorf("%w: name must be 1 to %d printable characters", ErrInvalid, MaxBBSNameLen)
	}
	return name, nil
}

// SetBBSName changes the BBS name.
func (s *Service) SetBBSName(ctx context.Context, actor int64, name string) error {
	name, err := NormalizeBBSName(name)
	if err != nil {
		return err
	}
	return s.set(ctx, actor, KeyBBSName, name)
}
