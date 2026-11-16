// Package perm implements groups and permissions (docs/DESIGN.md §4).
//
// Permissions are namespaced strings ("core.users.approve",
// "conferences.post"). Groups hold permissions; users hold groups; a user's
// effective permissions are the union over their groups. core.admin implies
// every permission. Only active accounts have permissions.
package perm

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Core permissions.
const (
	Admin        = "core.admin"         // implies every permission
	UsersApprove = "core.users.approve" // approve or reject pending accounts
	UsersManage  = "core.users.manage"  // lock/unlock accounts
	GroupsManage = "core.groups.manage" // create/delete groups, grant permissions, change membership
	InviteCreate = "core.invite.create" // create invites (own)
	InviteManage = "core.invite.manage" // list and revoke anyone's invites
)

var permName = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$`)

// Registry is the set of known permissions. Granting an unregistered
// permission is an error, so typos fail loudly.
type Registry struct {
	mu    sync.RWMutex
	perms map[string]string // name → description
}

// NewRegistry returns a registry containing the core permissions.
func NewRegistry() *Registry {
	return &Registry{perms: map[string]string{
		Admin:        "Full administration; implies every permission",
		UsersApprove: "Approve or reject pending accounts",
		UsersManage:  "Lock and unlock accounts",
		GroupsManage: "Manage groups, their permissions and members",
		InviteCreate: "Create invite codes",
		InviteManage: "List and revoke all invite codes",
	}}
}

// Register adds a permission. Plugins call this at startup.
func (r *Registry) Register(name, description string) error {
	if !permName.MatchString(name) {
		return fmt.Errorf("perm: invalid permission name %q", name)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.perms[name]; dup {
		return fmt.Errorf("perm: permission %q already registered", name)
	}
	r.perms[name] = description
	return nil
}

// Known reports whether name is registered.
func (r *Registry) Known(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.perms[name]
	return ok
}

// Permission is a registered permission and its description.
type Permission struct {
	Name, Description string
}

// All returns every registered permission sorted by name.
func (r *Registry) All() []Permission {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Permission, 0, len(r.perms))
	for n, d := range r.perms {
		out = append(out, Permission{n, d})
	}
	slices.SortFunc(out, func(a, b Permission) int { return strings.Compare(a.Name, b.Name) })
	return out
}

// Set is a user's effective permissions.
type Set map[string]bool

// Has reports whether the set grants p, directly or through core.admin.
func (s Set) Has(p string) bool { return s[Admin] || s[p] }
