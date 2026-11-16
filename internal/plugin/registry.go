package plugin

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

var (
	idPattern  = regexp.MustCompile(`^[a-z][a-z0-9]{1,30}$`)
	keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	// schemaObject finds objects a migration creates, alters or drops.
	schemaObject = regexp.MustCompile(`(?i)\b(?:CREATE\s+(?:UNIQUE\s+)?(?:TABLE|INDEX|VIEW|TRIGGER)|ALTER\s+TABLE|DROP\s+(?:TABLE|INDEX|VIEW|TRIGGER))\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?["\x60\[]?([A-Za-z0-9_]+)`)
	// onTable finds the table an index or trigger is attached to (and not
	// the ON DELETE / ON CONFLICT clauses of ordinary table definitions).
	onTable = regexp.MustCompile(`(?is)\bCREATE\s+(?:UNIQUE\s+)?(?:INDEX|TRIGGER)\b[^;]*?\bON\s+["\x60\[]?([A-Za-z0-9_]+)`)
)

// reservedIDs cannot be used as plugin IDs.
var reservedIDs = map[string]bool{"core": true, "system": true, "admin": true, "shellshawk": true}

// Deps are the core services handed to plugins.
type Deps struct {
	DB     *sql.DB
	Perms  *perm.Service
	Auth   *auth.Service
	Events *events.Bus
	Log    *slog.Logger
	Now    func() time.Time // nil = time.Now
}

// Loaded is a started plugin.
type Loaded struct {
	Manifest Manifest
	Settings *Settings
}

// Registry holds the started plugins.
type Registry struct {
	plugins []*Loaded
	items   map[string]Item // "<id>:<key>" → item
}

// Item is a menu item with its owning plugin.
type Item struct {
	Target   string // "<id>:<key>"
	PluginID string
	MenuItem
}

// Validate checks a manifest without starting anything.
func Validate(m Manifest) error {
	if !idPattern.MatchString(m.ID) || reservedIDs[m.ID] {
		return fmt.Errorf("plugin: invalid id %q (2-31 lowercase letters and digits, not reserved)", m.ID)
	}
	if m.Name == "" || m.Version == "" {
		return fmt.Errorf("plugin %s: name and version are required", m.ID)
	}
	for _, p := range m.Permissions {
		if !strings.HasPrefix(p.Name, m.ID+".") {
			return fmt.Errorf("plugin %s: permission %q must start with %q", m.ID, p.Name, m.ID+".")
		}
		for _, g := range p.DefaultGroups {
			if g == perm.GroupAdmin {
				return fmt.Errorf("plugin %s: permission %q: admin already has every permission", m.ID, p.Name)
			}
		}
	}
	seen := map[string]bool{}
	for _, s := range m.Settings {
		k := s.Field.Name
		if !keyPattern.MatchString(k) || seen[k] {
			return fmt.Errorf("plugin %s: invalid or duplicate setting %q", m.ID, k)
		}
		seen[k] = true
		f := s.Field
		if _, err := f.Validate(s.Default); err != nil {
			return fmt.Errorf("plugin %s: default for setting %q is invalid: %w", m.ID, k, err)
		}
	}
	for _, mg := range m.Migrations {
		if err := checkMigrationNames(m.ID, mg); err != nil {
			return err
		}
	}
	seen = map[string]bool{}
	for _, it := range m.MenuItems {
		if !keyPattern.MatchString(it.Key) || seen[it.Key] {
			return fmt.Errorf("plugin %s: invalid or duplicate menu item key %q", m.ID, it.Key)
		}
		seen[it.Key] = true
		if it.Label == "" || it.Run == nil {
			return fmt.Errorf("plugin %s: menu item %q needs a label and Run", m.ID, it.Key)
		}
	}
	return nil
}

// checkMigrationNames requires every schema object a plugin migration
// creates, alters or drops — and every table an index or trigger is
// attached to — to carry the "<id>_" prefix.
func checkMigrationNames(id string, mg store.Migration) error {
	prefix := strings.ToLower(id + "_")
	for _, m := range schemaObject.FindAllStringSubmatch(mg.SQL, -1) {
		if !strings.HasPrefix(strings.ToLower(m[1]), prefix) {
			return fmt.Errorf("plugin %s: migration %d touches %q; plugin tables must be named %s…", id, mg.Version, m[1], prefix)
		}
	}
	for _, m := range onTable.FindAllStringSubmatch(mg.SQL, -1) {
		if !strings.HasPrefix(strings.ToLower(m[1]), prefix) {
			return fmt.Errorf("plugin %s: migration %d attaches to %q, which is not the plugin's table", id, mg.Version, m[1])
		}
	}
	return nil
}

// Load validates, migrates and starts plugins in order. Any failure stops
// startup: a half-started plugin set is worse than a clear error.
func Load(ctx context.Context, d Deps, plugins ...Plugin) (*Registry, error) {
	if d.Now == nil {
		d.Now = time.Now
	}
	r := &Registry{items: map[string]Item{}}
	ids := map[string]bool{}
	for _, p := range plugins {
		m := p.Manifest()
		if err := Validate(m); err != nil {
			return nil, err
		}
		if ids[m.ID] {
			return nil, fmt.Errorf("plugin: duplicate id %q", m.ID)
		}
		ids[m.ID] = true

		log := d.Log.With("plugin", m.ID)
		for _, pm := range m.Permissions {
			if err := d.Perms.Registry().Register(pm.Name, pm.Description); err != nil {
				return nil, fmt.Errorf("plugin %s: %w", m.ID, err)
			}
		}
		if err := store.Migrate(ctx, d.DB, m.ID, m.Migrations, log); err != nil {
			return nil, fmt.Errorf("plugin %s: %w", m.ID, err)
		}
		if err := seedGrants(ctx, d.DB, m, log); err != nil {
			return nil, err
		}
		st := &Settings{id: m.ID, defs: m.Settings, db: d.DB, now: d.Now, log: log}
		h := &Host{ID: m.ID, DB: d.DB, Perms: d.Perms, Auth: d.Auth, Events: d.Events, Settings: st, Log: log}
		if err := p.Init(ctx, h); err != nil {
			return nil, fmt.Errorf("plugin %s: init: %w", m.ID, err)
		}
		for _, it := range m.MenuItems {
			t := m.ID + ":" + it.Key
			r.items[t] = Item{Target: t, PluginID: m.ID, MenuItem: it}
		}
		r.plugins = append(r.plugins, &Loaded{Manifest: m, Settings: st})
		log.Info("plugin started", "version", m.Version, "menu_items", len(m.MenuItems), "permissions", len(m.Permissions))
	}
	return r, nil
}

// Plugins returns the started plugins in load order.
func (r *Registry) Plugins() []*Loaded { return r.plugins }

// Item returns the menu item for target.
func (r *Registry) Item(target string) (Item, bool) {
	it, ok := r.items[target]
	return it, ok
}

// Items returns all plugin menu items, sorted by target.
func (r *Registry) Items() []Item {
	out := make([]Item, 0, len(r.items))
	for _, it := range r.items {
		out = append(out, it)
	}
	slices.SortFunc(out, func(a, b Item) int { return strings.Compare(a.Target, b.Target) })
	return out
}

// seedGrants grants each permission to its default groups the first time
// the plugin is loaded. Later changes by administrators are never undone:
// a seeded permission is not granted again on the next start.
func seedGrants(ctx context.Context, db *sql.DB, m Manifest, log *slog.Logger) error {
	return store.WithTx(ctx, db, func(tx *sql.Tx) error {
		for _, p := range m.Permissions {
			res, err := tx.ExecContext(ctx, `INSERT INTO plugin_grants_seeded (permission) VALUES (?) ON CONFLICT DO NOTHING`, p.Name)
			if err != nil {
				return fmt.Errorf("plugin %s: seed grants: %w", m.ID, err)
			}
			if n, _ := res.RowsAffected(); n == 0 {
				continue // seeded on an earlier start
			}
			for _, g := range p.DefaultGroups {
				res, err := tx.ExecContext(ctx, `
					INSERT INTO access_group_permissions (group_id, permission)
					SELECT id, ? FROM access_groups WHERE name = ? ON CONFLICT DO NOTHING`, p.Name, g)
				if err != nil {
					return fmt.Errorf("plugin %s: grant %s to %s: %w", m.ID, p.Name, g, err)
				}
				if n, _ := res.RowsAffected(); n > 0 {
					log.Info("default permission granted", "permission", p.Name, "group", g)
				} else {
					log.Warn("default group missing; permission not granted", "permission", p.Name, "group", g)
				}
			}
		}
		return nil
	})
}
