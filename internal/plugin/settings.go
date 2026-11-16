package plugin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// Settings reads and writes one plugin's settings. Values are validated
// against the plugin's declared fields; unset values return the default.
type Settings struct {
	id   string
	defs []Setting
	db   *sql.DB
	now  func() time.Time
	log  *slog.Logger
}

// Defs returns the plugin's declared settings.
func (s *Settings) Defs() []Setting { return s.defs }

func (s *Settings) def(key string) (Setting, bool) {
	for _, d := range s.defs {
		if d.Field.Name == key {
			return d, true
		}
	}
	return Setting{}, false
}

// Get returns a setting's value, or its default. A stored value that no
// longer validates (e.g. the field's rules changed) also yields the default.
func (s *Settings) Get(ctx context.Context, key string) (string, error) {
	d, ok := s.def(key)
	if !ok {
		return "", fmt.Errorf("plugin %s: unknown setting %q", s.id, key)
	}
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM plugin_settings WHERE plugin_id = ? AND key = ?`, s.id, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return d.Default, nil
	}
	if err != nil {
		return "", fmt.Errorf("plugin %s: get setting %s: %w", s.id, key, err)
	}
	if _, verr := d.Field.Validate(v); verr != nil {
		s.log.Warn("stored setting no longer valid; using default", "key", key, "err", verr)
		return d.Default, nil
	}
	return v, nil
}

// All returns every setting's current value.
func (s *Settings) All(ctx context.Context) (form.Values, error) {
	out := form.Values{}
	for _, d := range s.defs {
		v, err := s.Get(ctx, d.Field.Name)
		if err != nil {
			return nil, err
		}
		out[d.Field.Name] = v
	}
	return out, nil
}

// Form returns the settings as a form.
func (s *Settings) Form(title string) *form.Form {
	fm := &form.Form{Title: title}
	for _, d := range s.defs {
		fm.Fields = append(fm.Fields, d.Field)
	}
	return fm
}

// Save validates and stores values as actor, who needs
// core.plugins.settings. It returns field errors for invalid values.
func (s *Settings) Save(ctx context.Context, actor int64, values form.Values) (form.Errors, error) {
	fm := s.Form("")
	clean, errs := fm.Validate(values)
	if len(errs) > 0 {
		return errs, nil
	}
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := perm.RequireTx(ctx, tx, actor, perm.PluginSettings); err != nil {
			return err
		}
		now := s.now()
		for _, d := range s.defs {
			k := d.Field.Name
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO plugin_settings (plugin_id, key, value, updated_at) VALUES (?, ?, ?, ?)
				ON CONFLICT (plugin_id, key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
				s.id, k, clean[k], store.FormatTime(now)); err != nil {
				return fmt.Errorf("plugin %s: save setting %s: %w", s.id, k, err)
			}
		}
		return audit.Record(ctx, tx, now, audit.Entry{Actor: actor, Action: audit.PluginSettingSet, TargetType: "plugin", Detail: s.id})
	})
	if err != nil {
		return nil, err
	}
	s.log.Info("plugin settings changed", "actor", actor)
	return nil, nil
}
