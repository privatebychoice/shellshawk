package perm

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/store"
)

type fixture struct {
	t   *testing.T
	ctx context.Context
	db  *sql.DB
	svc *Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "perm.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &fixture{t: t, ctx: ctx, db: db, svc: NewService(db, NewRegistry(), nil, log)}
}

// user inserts an account directly (auth is tested separately) and adds it
// to the named groups.
func (f *fixture) user(name, status string, groups ...string) int64 {
	f.t.Helper()
	res, err := f.db.ExecContext(f.ctx, `INSERT INTO users (username, password_hash, status, created_at) VALUES (?, 'x', ?, ?)`,
		name, status, store.FormatTime(time.Now()))
	if err != nil {
		f.t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	for _, g := range groups {
		grp, err := f.svc.GroupByName(f.ctx, g)
		if err != nil {
			f.t.Fatal(err)
		}
		if err := AddMemberSystem(f.ctx, f.db, id, grp.ID); err != nil {
			f.t.Fatal(err)
		}
	}
	return id
}

func (f *fixture) group(name string) int64 {
	f.t.Helper()
	g, err := f.svc.GroupByName(f.ctx, name)
	if err != nil {
		f.t.Fatal(err)
	}
	return g.ID
}

func TestRegistry(t *testing.T) {
	r := NewRegistry()
	tests := []struct {
		name string
		ok   bool
	}{
		{"conferences.post", true},
		{"chat.channel.create", true},
		{"core.admin", false}, // duplicate
		{"nodot", false},
		{"Bad.Case", false},
		{"trailing.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := r.Register(tt.name, "d"); (err == nil) != tt.ok {
				t.Errorf("Register(%q) = %v, ok %v", tt.name, err, tt.ok)
			}
		})
	}
	if !r.Known("conferences.post") || r.Known("nope.nope") {
		t.Error("Known() wrong")
	}
	all := r.All()
	for i := 1; i < len(all); i++ {
		if all[i-1].Name > all[i].Name {
			t.Fatal("All() not sorted")
		}
	}
}

func TestEffectivePermissions(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin1", "active", GroupAdmin)
	mod := f.user("mod1", "active", GroupModerator)
	member := f.user("member1", "active", GroupMember)
	pendingMod := f.user("pmod", "pending", GroupModerator)
	lockedAdmin := f.user("ladmin", "locked", GroupAdmin)

	tests := []struct {
		name string
		user int64
		perm string
		want bool
	}{
		{"admin implies everything", admin, "anything.at_all", true},
		{"moderator approves", mod, UsersApprove, true},
		{"moderator cannot manage groups", mod, GroupsManage, false},
		{"member has nothing core", member, InviteCreate, false},
		{"pending account has no permissions", pendingMod, UsersApprove, false},
		{"locked account has no permissions", lockedAdmin, Admin, false},
		{"unknown user", 9999, UsersApprove, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := f.svc.Has(f.ctx, tt.user, tt.perm)
			if err != nil || got != tt.want {
				t.Errorf("Has = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
	if err := f.svc.Require(f.ctx, member, UsersApprove); !errors.Is(err, ErrForbidden) {
		t.Errorf("Require err = %v", err)
	}
}

func TestGroupManagementEscalation(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin1", "active", GroupAdmin)
	member := f.user("member1", "active", GroupMember)

	// A "managers" group may manage groups but is not admin.
	managers, err := f.svc.CreateGroup(f.ctx, admin, "Managers", "group managers")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Grant(f.ctx, admin, managers, GroupsManage); err != nil {
		t.Fatal(err)
	}
	mgr := f.user("mgr1", "active")
	if err := f.svc.AddMember(f.ctx, admin, managers, mgr); err != nil {
		t.Fatal(err)
	}
	f.svc.Registry().Register("conferences.post", "post")

	tests := []struct {
		name string
		do   func() error
		want error
	}{
		{"member cannot create groups", func() error { _, err := f.svc.CreateGroup(f.ctx, member, "x1", ""); return err }, ErrForbidden},
		{"invalid group name", func() error { _, err := f.svc.CreateGroup(f.ctx, admin, "Bad Name!", ""); return err }, ErrInvalidGroup},
		{"duplicate group name", func() error { _, err := f.svc.CreateGroup(f.ctx, admin, "MANAGERS", ""); return err }, ErrExists},
		{"unknown permission", func() error { return f.svc.Grant(f.ctx, admin, managers, "no.such_perm") }, ErrUnknownPerm},
		{"manager cannot grant core.admin", func() error { return f.svc.Grant(f.ctx, mgr, managers, Admin) }, ErrForbidden},
		{"manager cannot grant perms they lack", func() error { return f.svc.Grant(f.ctx, mgr, f.group(GroupMember), "conferences.post") }, ErrForbidden},
		{"manager cannot join admin group", func() error { return f.svc.AddMember(f.ctx, mgr, f.group(GroupAdmin), mgr) }, ErrForbidden},
		{"manager cannot add others to moderators", func() error { return f.svc.AddMember(f.ctx, mgr, f.group(GroupModerator), member) }, ErrForbidden},
		{"manager can add to member group", func() error { return f.svc.AddMember(f.ctx, mgr, f.group(GroupMember), mgr) }, nil},
		{"admin keeps core.admin", func() error { return f.svc.Revoke(f.ctx, admin, f.group(GroupAdmin), Admin) }, ErrProtected},
		{"built-in group cannot be deleted", func() error { return f.svc.DeleteGroup(f.ctx, admin, f.group(GroupMember)) }, ErrProtected},
		{"sole admin cannot leave admin group", func() error { return f.svc.RemoveMember(f.ctx, admin, f.group(GroupAdmin), admin) }, ErrLastAdmin},
		{"remove non-member", func() error { return f.svc.RemoveMember(f.ctx, admin, f.group(GroupModerator), member) }, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.do(); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}

	// With a second admin, the first may step down.
	admin2 := f.user("admin2", "active", GroupAdmin)
	if err := f.svc.RemoveMember(f.ctx, admin2, f.group(GroupAdmin), admin); err != nil {
		t.Errorf("second admin removing first: %v", err)
	}
	if err := f.svc.DeleteGroup(f.ctx, admin2, managers); err != nil {
		t.Errorf("DeleteGroup: %v", err)
	}
	if ok, _ := f.svc.Has(f.ctx, mgr, GroupsManage); ok {
		t.Error("permission survived group deletion")
	}

	var audits int
	f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE action LIKE 'group.%'`).Scan(&audits)
	if audits < 5 {
		t.Errorf("group changes audited = %d", audits)
	}
}

func TestRequireOutranks(t *testing.T) {
	f := newFixture(t)
	admin := f.user("admin1", "active", GroupAdmin)
	mod := f.user("mod1", "active", GroupModerator)
	pendingAdmin := f.user("padmin", "pending", GroupAdmin)
	member := f.user("member1", "active", GroupMember)

	tests := []struct {
		name          string
		actor, target int64
		want          error
	}{
		{"admin outranks anyone", admin, pendingAdmin, nil},
		{"moderator outranks member", mod, member, nil},
		{"moderator does not outrank pending admin", mod, pendingAdmin, ErrForbidden},
		{"member lacks the permission", member, mod, ErrForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := RequireOutranks(f.ctx, f.db, tt.actor, tt.target, UsersApprove); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}
