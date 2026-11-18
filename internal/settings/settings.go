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
	"maps"
	"slices"
	"strconv"
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
	KeyBBSName     = "branding.name"
	KeyIdleTimeout = "ssh.idle_timeout_minutes"
	KeyMaxPerUser  = "ssh.max_connections_per_user"
)

// Connection limit defaults and bounds.
const (
	DefaultIdleMinutes = 30
	MinIdleMinutes     = 2 // leaves room for the one-minute warning
	MaxIdleMinutes     = 24 * 60
	DefaultMaxPerUser  = 3
	MaxMaxPerUser      = 20
)

// ConnLimits are the SSH connection limits. A zero field turns that limit
// off.
type ConnLimits struct {
	IdleMinutes int // end a connection after this many minutes without activity
	MaxPerUser  int // connections one account may have open at once
}

// DefaultConnLimits apply until an administrator changes them.
var DefaultConnLimits = ConnLimits{IdleMinutes: DefaultIdleMinutes, MaxPerUser: DefaultMaxPerUser}

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
	return s.setMany(ctx, actor, map[string]string{key: value})
}

// setMany writes several settings in one transaction, auditing each.
func (s *Service) setMany(ctx context.Context, actor int64, values map[string]string) error {
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := perm.RequireTx(ctx, tx, actor, perm.SettingsManage); err != nil {
			return err
		}
		now := s.now()
		for _, key := range slices.Sorted(maps.Keys(values)) {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)
				ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
				key, values[key], store.FormatTime(now)); err != nil {
				return fmt.Errorf("settings: set %s: %w", key, err)
			}
			s.log.Info("setting changed", "actor", actor, "key", key)
			if err := audit.Record(ctx, tx, now, audit.Entry{Actor: actor, Action: audit.SettingChanged, TargetType: "setting", Detail: key}); err != nil {
				return err
			}
		}
		return nil
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

// ConnLimits returns the SSH connection limits, falling back to the defaults
// for a value that cannot be read so a database problem never removes them.
func (s *Service) ConnLimits(ctx context.Context) ConnLimits {
	read := func(key string, def int) int {
		v, err := s.get(ctx, key, strconv.Itoa(def))
		if err != nil {
			s.log.Error("read connection limit", "key", key, "err", err)
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			s.log.Error("stored connection limit is not a number", "key", key)
			return def
		}
		return n
	}
	return ConnLimits{
		IdleMinutes: read(KeyIdleTimeout, DefaultIdleMinutes),
		MaxPerUser:  read(KeyMaxPerUser, DefaultMaxPerUser),
	}
}

// CheckIdleMinutes validates an idle timeout: 0 (off) or MinIdleMinutes to
// MaxIdleMinutes.
func CheckIdleMinutes(n int) error {
	if n != 0 && (n < MinIdleMinutes || n > MaxIdleMinutes) {
		return fmt.Errorf("%w: idle timeout must be 0 (off) or %d to %d minutes", ErrInvalid, MinIdleMinutes, MaxIdleMinutes)
	}
	return nil
}

// CheckMaxPerUser validates a per-account connection limit: 0 (no limit)
// to MaxMaxPerUser.
func CheckMaxPerUser(n int) error {
	if n < 0 || n > MaxMaxPerUser {
		return fmt.Errorf("%w: connections per account must be 0 (no limit) to %d", ErrInvalid, MaxMaxPerUser)
	}
	return nil
}

// SetConnLimits changes the SSH connection limits. They apply to open
// connections at once.
func (s *Service) SetConnLimits(ctx context.Context, actor int64, l ConnLimits) error {
	if err := errors.Join(CheckIdleMinutes(l.IdleMinutes), CheckMaxPerUser(l.MaxPerUser)); err != nil {
		return err
	}
	cur := s.ConnLimits(ctx)
	changed := map[string]string{}
	if l.IdleMinutes != cur.IdleMinutes {
		changed[KeyIdleTimeout] = strconv.Itoa(l.IdleMinutes)
	}
	if l.MaxPerUser != cur.MaxPerUser {
		changed[KeyMaxPerUser] = strconv.Itoa(l.MaxPerUser)
	}
	return s.setMany(ctx, actor, changed) // checks permission even when nothing changed
}
