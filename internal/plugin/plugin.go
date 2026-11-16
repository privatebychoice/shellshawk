// Package plugin is shellshawk's compiled-in extension system
// (docs/DESIGN.md §3.1). A plugin is a Go package that implements Plugin and
// is listed in the server's plugin set at build time; there is no runtime
// loading of code.
//
// A plugin declares everything up front in its Manifest — permissions,
// admin-editable settings, schema migrations and menu items — and receives a
// Host with the core services when it starts.
package plugin

import (
	"context"
	"database/sql"
	"log/slog"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/presence"
	"go.privatebychoice.com/shellshawk/internal/privacy"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// Plugin is implemented by every plugin.
type Plugin interface {
	Manifest() Manifest
	// Init is called once at startup, after the plugin's permissions are
	// registered and its migrations applied. Menu items run only after
	// every plugin's Init has succeeded.
	Init(ctx context.Context, h *Host) error
}

// Manifest describes a plugin.
type Manifest struct {
	// ID is a short lowercase identifier (letters and digits, 2-31
	// characters). It prefixes the plugin's permissions ("<id>.post"), its
	// tables ("<id>_posts") and its menu items ("<id>:main").
	ID          string
	Name        string
	Version     string
	Description string

	// Permissions the plugin defines; each name must start with "<id>.".
	Permissions []Permission
	// Settings administrators can change from Administration > Plugin
	// settings. Each is a standard form field with a default.
	Settings []Setting
	// Migrations create and change the plugin's own tables, all of which
	// must be named "<id>_…". They run in order, tracked separately from
	// core and other plugins.
	Migrations []store.Migration
	// MenuItems can be placed in the member menu. New items are added to
	// the main menu automatically, once; administrators can then move,
	// rename or remove them.
	MenuItems []MenuItem
	// SFTP mounts are top-level SFTP directories. Each name must be the
	// plugin ID or start with "<id>-".
	SFTP []sftpd.Mount
	// Export returns everything the plugin stores about a member, for the
	// data export at /me/export/<id>/ (right of access). Plugins that store
	// member data must provide it, and must also handle events.UserErased.
	Export func(ctx context.Context, userID int64) ([]export.File, error)
}

// Permission is a permission a plugin defines.
type Permission struct {
	Name        string
	Description string
	// DefaultGroups receive the permission the first time the plugin is
	// loaded. Groups do not inherit from each other, so an everyday
	// permission should list both "member" and "moderator" (an account
	// invited straight into "moderator" is not in "member").
	// Administrators can change it afterwards; it is never re-granted.
	DefaultGroups []string
}

// Setting is an administrator-editable plugin setting.
type Setting struct {
	Field   form.Field // Field.Name is the setting key
	Default string     // must pass Field.Validate
}

// MenuItem is something a member can open from the menu.
type MenuItem struct {
	Key   string // unique within the plugin; the item is "<id>:<key>"
	Label string // default menu label
	Help  string
	// AnyOf lists permissions of which the member needs at least one; empty
	// means every logged-in member may use the item.
	AnyOf []string
	// Run shows the item. It returns when the member is done. Errors and
	// panics are caught, logged and reported to the member as a generic
	// failure; they never end the session.
	Run func(ctx context.Context, s Session) error
}

// Allowed reports whether a member with set may use the item.
func (m MenuItem) Allowed(set perm.Set) bool {
	if len(m.AnyOf) == 0 {
		return true
	}
	for _, p := range m.AnyOf {
		if set.Has(p) {
			return true
		}
	}
	return false
}

// Session is what a menu item can do in a member's session.
type Session interface {
	// UI is the member's interface (full-screen or screen-reader line mode).
	UI() tui.UI
	// UserID is the logged-in member.
	UserID() int64
	// Title prefixes a screen title with the BBS name.
	Title(t string) string
	// Form shows a form with the BBS name in its title.
	Form(ctx context.Context, fm *form.Form, values form.Values, errs form.Errors) (form.Values, error)
	// Markdown renders markdown for this member's interface, grading links.
	Markdown(title, src string) tui.Page
	// Permissions returns the member's current permissions.
	Permissions(ctx context.Context) (perm.Set, error)
	// Log is a logger tagged with the session and plugin.
	Log() *slog.Logger
}

// Host gives a plugin access to the core services.
//
// Plugins are compiled-in, trusted code: DB is the shared database handle.
// By convention a plugin only touches its own "<id>_" tables and uses the
// services below for anything else; migrations enforce the naming, but the
// convention is not a security boundary.
type Host struct {
	ID       string
	DB       *sql.DB
	Perms    *perm.Service
	Auth     *auth.Service
	Events   *events.Bus
	Presence *presence.Tracker // who has a BBS session open; may be nil in tests
	Privacy  *privacy.Service  // visibility rules; may be nil in tests
	Settings *Settings         // this plugin's settings only
	Log      *slog.Logger
}
