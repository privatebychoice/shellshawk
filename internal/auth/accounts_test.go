package auth

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/perm"
)

func TestBootstrap(t *testing.T) {
	f := newFixture(t)
	if ok, _ := f.perms.Has(f.ctx, f.admin, perm.Admin); !ok {
		t.Fatal("bootstrap account is not an administrator")
	}
	u, _ := f.svc.UserByID(f.ctx, f.admin)
	if u.Status != StatusActive {
		t.Errorf("bootstrap account status = %s, want active", u.Status)
	}
	if _, err := f.svc.CreateBootstrapInvite(f.ctx); !errors.Is(err, ErrBootstrapDone) {
		t.Errorf("second bootstrap err = %v, want ErrBootstrapDone", err)
	}
}

func TestBootstrapRevokesPrevious(t *testing.T) {
	f := newEmptyFixture(t)
	first, err := f.svc.CreateBootstrapInvite(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.svc.CreateBootstrapInvite(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CheckInvite(f.ctx, first); !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("first bootstrap invite still valid: %v", err)
	}
	if _, err := f.svc.CheckInvite(f.ctx, second); err != nil {
		t.Errorf("second bootstrap invite invalid: %v", err)
	}
}

func TestRegister(t *testing.T) {
	f := newFixture(t)
	takenKey, _ := newKeyLine(t, "")
	if _, err := f.svc.Register(f.ctx, f.invite(f.admin, InviteOptions{}),
		Registration{Username: "existing", Password: testPassword, PublicKey: takenKey}); err != nil {
		t.Fatal(err)
	}

	type reg struct {
		code     func() string
		username string
		password string
		email    string
		key      string
	}
	fresh := func() string { line, _ := newKeyLine(t, ""); return line }
	valid := func() string { return f.invite(f.admin, InviteOptions{}) }
	expired := func() string {
		code := f.invite(f.admin, InviteOptions{TTL: time.Hour})
		f.clk.Advance(2 * time.Hour)
		return code
	}
	usedUp := func() string {
		code := valid()
		f.register(code, "usedup1")
		return code
	}
	revoked := func() string {
		code, inv, err := f.svc.CreateInvite(f.ctx, f.admin, InviteOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if err := f.svc.RevokeInvite(f.ctx, f.admin, inv.ID); err != nil {
			t.Fatal(err)
		}
		return code
	}

	tests := []struct {
		name string
		r    reg
		want error
	}{
		{"ok", reg{valid, "Alice", testPassword, "a@example.org", fresh()}, nil},
		{"bad code", reg{func() string { return "NOPE-NOPE" }, "bob", testPassword, "", fresh()}, ErrInviteInvalid},
		{"expired", reg{expired, "carol", testPassword, "", fresh()}, ErrInviteInvalid},
		{"used up", reg{usedUp, "dave", testPassword, "", fresh()}, ErrInviteInvalid},
		{"revoked", reg{revoked, "erin", testPassword, "", fresh()}, ErrInviteInvalid},
		{"username taken (case-insensitive)", reg{valid, "EXISTING", testPassword, "", fresh()}, ErrUsernameTaken},
		{"reserved username", reg{valid, "sysop", testPassword, "", fresh()}, ErrUsernameReserved},
		{"short password", reg{valid, "frank", "short", "", fresh()}, ErrPasswordPolicy},
		{"bad email", reg{valid, "grace", testPassword, "nope", fresh()}, ErrEmailInvalid},
		{"key already registered", reg{valid, "heidi", testPassword, "", takenKey}, ErrKeyInUse},
		{"bad key", reg{valid, "ivan", testPassword, "", "ssh-ed25519 junk"}, ErrKeyInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := tt.r.code()
			u, err := f.svc.Register(f.ctx, code, Registration{
				Username: tt.r.username, Password: tt.r.password, Email: tt.r.email, PublicKey: tt.r.key,
			})
			if !errors.Is(err, tt.want) {
				t.Fatalf("Register err = %v, want %v", err, tt.want)
			}
			if tt.want != nil {
				// A failed registration must not consume the invite.
				if inv, err := f.svc.CheckInvite(f.ctx, code); err == nil && inv.Uses != 0 {
					t.Errorf("failed registration consumed an invite use")
				}
				return
			}
			if u.Username != "alice" || u.Status != StatusActive || u.Email != tt.r.email {
				t.Errorf("user = %+v", u)
			}
			groups, _ := f.perms.UserGroups(f.ctx, u.ID)
			if !slices.Equal(groups, []string{perm.GroupMember}) {
				t.Errorf("groups = %v, want [member]", groups)
			}
		})
	}
	if n := f.auditCount(audit.UserRegistered); n < 3 {
		t.Errorf("user.registered audit entries = %d", n)
	}
}

func TestMultiUseInvite(t *testing.T) {
	f := newFixture(t)
	code := f.invite(f.admin, InviteOptions{MaxUses: 2})
	f.register(code, "one11")
	f.register(code, "two22")
	line, _ := newKeyLine(t, "")
	_, err := f.svc.Register(f.ctx, code, Registration{Username: "three", Password: testPassword, PublicKey: line})
	if !errors.Is(err, ErrInviteInvalid) {
		t.Errorf("third use err = %v, want ErrInviteInvalid", err)
	}
}

func TestInvitePermissions(t *testing.T) {
	f := newFixture(t)
	mod := f.user("mod1", perm.GroupModerator)
	member := f.user("member1")
	// "vips" grants nothing but opens group-only content: only its own
	// members (and administrators) may invite into it.
	if _, err := f.perms.CreateGroup(f.ctx, f.admin, "vips", ""); err != nil {
		t.Fatal(err)
	}
	vipMod := f.user("mod2", perm.GroupModerator, "vips")

	tests := []struct {
		name  string
		actor int64
		opt   InviteOptions
		want  error
	}{
		{"admin, admin group", f.admin, InviteOptions{Groups: []string{perm.GroupAdmin}}, nil},
		{"moderator, default group", mod, InviteOptions{}, nil},
		{"moderator, moderator group", mod, InviteOptions{Groups: []string{perm.GroupModerator}}, nil},
		{"moderator cannot invite admins", mod, InviteOptions{Groups: []string{perm.GroupAdmin}}, perm.ErrForbidden},
		{"moderator not in vips cannot invite into it", mod, InviteOptions{Groups: []string{"vips"}}, perm.ErrForbidden},
		{"moderator in vips invites into it", vipMod, InviteOptions{Groups: []string{"vips"}}, nil},
		{"admin invites into any group", f.admin, InviteOptions{Groups: []string{"vips"}}, nil},
		{"member cannot invite", member, InviteOptions{}, perm.ErrForbidden},
		{"unknown group", f.admin, InviteOptions{Groups: []string{"nope"}}, perm.ErrNotFound},
		{"too many uses", f.admin, InviteOptions{MaxUses: MaxInviteUses + 1}, ErrInviteOptions},
		{"ttl too long", f.admin, InviteOptions{TTL: MaxInviteTTL + time.Hour}, ErrInviteOptions},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := f.svc.CreateInvite(f.ctx, tt.actor, tt.opt)
			if !errors.Is(err, tt.want) {
				t.Errorf("CreateInvite err = %v, want %v", err, tt.want)
			}
		})
	}

	// Listing: moderators see their own, admins (core.admin ⊇ invite.manage) see all.
	modInvites, _ := f.svc.Invites(f.ctx, mod)
	allInvites, _ := f.svc.Invites(f.ctx, f.admin)
	if len(modInvites) != 2 || len(allInvites) <= len(modInvites) {
		t.Errorf("moderator sees %d invites, admin sees %d", len(modInvites), len(allInvites))
	}
	if _, err := f.svc.Invites(f.ctx, member); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member list err = %v", err)
	}
	// Moderator cannot revoke an admin's invite; admin can revoke a moderator's.
	adminInv := allInvites[len(allInvites)-1]
	if err := f.svc.RevokeInvite(f.ctx, mod, adminInv.ID); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("moderator revoking admin invite err = %v", err)
	}
	if err := f.svc.RevokeInvite(f.ctx, f.admin, modInvites[0].ID); err != nil {
		t.Errorf("admin revoke err = %v", err)
	}
}

func TestApproval(t *testing.T) {
	f := newFixture(t)
	mod := f.user("mod1", perm.GroupModerator)
	member := f.user("member1")

	pendingMember := f.register(f.invite(f.admin, InviteOptions{RequireApproval: true}), "pending1")
	pendingAdmin := f.register(f.invite(f.admin, InviteOptions{RequireApproval: true, Groups: []string{perm.GroupAdmin}}), "pending2")
	toReject := f.register(f.invite(f.admin, InviteOptions{RequireApproval: true}), "pending3")

	if pendingMember.Status != StatusPending {
		t.Fatalf("status = %s, want pending", pendingMember.Status)
	}
	if ok, _ := f.perms.Has(f.ctx, pendingAdmin.ID, perm.Admin); ok {
		t.Fatal("pending account has permissions before approval")
	}

	list, err := f.svc.PendingUsers(f.ctx, mod)
	if err != nil || len(list) != 3 {
		t.Fatalf("PendingUsers = %d, %v", len(list), err)
	}
	if _, err := f.svc.PendingUsers(f.ctx, member); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member PendingUsers err = %v", err)
	}

	tests := []struct {
		name   string
		actor  int64
		target int64
		reject bool
		want   error
	}{
		{"member cannot approve", member, pendingMember.ID, false, perm.ErrForbidden},
		{"moderator cannot approve an admin", mod, pendingAdmin.ID, false, perm.ErrForbidden},
		{"moderator approves member", mod, pendingMember.ID, false, nil},
		{"already approved", mod, pendingMember.ID, false, ErrNotPending},
		{"admin approves admin", f.admin, pendingAdmin.ID, false, nil},
		{"moderator rejects", mod, toReject.ID, true, nil},
		{"cannot reject active account", mod, member, true, ErrNotPending},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.reject {
				err = f.svc.Reject(f.ctx, tt.actor, tt.target)
			} else {
				err = f.svc.Approve(f.ctx, tt.actor, tt.target)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}

	if ok, _ := f.perms.Has(f.ctx, pendingAdmin.ID, perm.Admin); !ok {
		t.Error("approved admin lacks permissions")
	}
	if _, err := f.svc.UserByID(f.ctx, toReject.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("rejected account still exists: %v", err)
	}
	var keys int
	f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM user_keys WHERE user_id = ?`, toReject.ID).Scan(&keys)
	if keys != 0 {
		t.Error("rejected account's keys were not deleted")
	}
}

func TestKeys(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	bob := f.user("bobby")

	// alice has 1 key from registration; two more fit, a fourth does not.
	for i := range 2 {
		line, _ := newKeyLine(t, "extra")
		if _, err := f.svc.AddKey(f.ctx, alice, line, ""); err != nil {
			t.Fatalf("AddKey %d: %v", i, err)
		}
	}
	line, _ := newKeyLine(t, "")
	if _, err := f.svc.AddKey(f.ctx, alice, line, ""); !errors.Is(err, ErrKeyLimit) {
		t.Errorf("fourth key err = %v, want ErrKeyLimit", err)
	}

	keys, _ := f.svc.Keys(f.ctx, alice)
	if len(keys) != MaxKeysPerUser || keys[1].Label != "extra" {
		t.Fatalf("keys = %+v", keys)
	}
	// Bob cannot remove or reuse Alice's key.
	if err := f.svc.RemoveKey(f.ctx, bob, keys[0].ID); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("bob removing alice's key err = %v", err)
	}
	var aliceLine string
	f.db.QueryRowContext(f.ctx, `SELECT public_key FROM user_keys WHERE id = ?`, keys[0].ID).Scan(&aliceLine)
	if _, err := f.svc.AddKey(f.ctx, bob, aliceLine, ""); !errors.Is(err, ErrKeyInUse) {
		t.Errorf("bob adding alice's key err = %v", err)
	}
	if err := f.svc.RemoveKey(f.ctx, alice, keys[0].ID); err != nil {
		t.Errorf("RemoveKey: %v", err)
	}
	if _, err := f.svc.AddKey(f.ctx, alice, line, "  label\x1b[31m "); err != nil {
		t.Errorf("AddKey after removal: %v", err)
	}
	keys, _ = f.svc.Keys(f.ctx, alice)
	if got := keys[len(keys)-1].Label; got != "label[31m" {
		t.Errorf("label not sanitized: %q", got)
	}
	if f.auditCount(audit.KeyAdded) < 5 || f.auditCount(audit.KeyRemoved) != 1 {
		t.Error("key changes not audited")
	}
}

func TestSetLocked(t *testing.T) {
	f := newFixture(t)
	member := f.user("member1")
	mod := f.user("mod1", perm.GroupModerator)

	if err := f.svc.SetLocked(f.ctx, f.admin, f.admin, true); !errors.Is(err, ErrSelf) {
		t.Errorf("lock self err = %v", err)
	}
	if err := f.svc.SetLocked(f.ctx, mod, member, true); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("moderator lacks users.manage, err = %v", err)
	}
	if err := f.svc.SetLocked(f.ctx, f.admin, member, true); err != nil {
		t.Fatalf("lock: %v", err)
	}
	u, _ := f.svc.UserByID(f.ctx, member)
	if u.Status != StatusLocked {
		t.Errorf("status = %s", u.Status)
	}
	if err := f.svc.SetLocked(f.ctx, f.admin, member, true); !errors.Is(err, ErrNotFound) {
		t.Errorf("double lock err = %v", err)
	}
	if err := f.svc.SetLocked(f.ctx, f.admin, member, false); err != nil {
		t.Errorf("unlock: %v", err)
	}
}

func TestSingleUseInviteUnderConcurrency(t *testing.T) {
	f := newFixture(t)
	code := f.invite(f.admin, InviteOptions{MaxUses: 1})

	const racers = 8
	errs := make(chan error, racers)
	for i := range racers {
		go func() {
			line, _ := newKeyLine(t, "")
			_, err := f.svc.Register(f.ctx, code, Registration{
				Username: "racer" + string(rune('a'+i)), Password: testPassword, PublicKey: line,
			})
			errs <- err
		}()
	}
	ok := 0
	for range racers {
		err := <-errs
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrInviteInvalid):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Errorf("%d registrations succeeded with a single-use invite, want exactly 1", ok)
	}
}

func TestListUsers(t *testing.T) {
	f := newFixture(t)
	f.user("anna_b")
	f.user("annaxb") // must not match the literal prefix "anna_"
	member := f.user("member1")

	tests := []struct {
		name   string
		actor  int64
		prefix string
		want   []string
		err    error
	}{
		{"prefix is literal, not a wildcard", f.admin, "ANNA_", []string{"anna_b"}, nil},
		{"all", f.admin, "", []string{"anna_b", "annaxb", "member1", "sysadmin1"}, nil},
		{"member forbidden", member, "", nil, perm.ErrForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := f.svc.ListUsers(f.ctx, tt.actor, tt.prefix)
			if !errors.Is(err, tt.err) {
				t.Fatalf("err = %v", err)
			}
			var names []string
			for _, u := range got {
				names = append(names, u.Username)
			}
			if !slices.Equal(names, tt.want) {
				t.Errorf("users = %v, want %v", names, tt.want)
			}
		})
	}
}

type recordingPublisher struct{ got []events.Event }

func (r *recordingPublisher) Publish(_ context.Context, e events.Event) error {
	r.got = append(r.got, e)
	return nil
}

func TestAccountEvents(t *testing.T) {
	f := newFixture(t)
	pub := &recordingPublisher{}
	f.svc.SetPublisher(pub)

	pending := f.register(f.invite(f.admin, InviteOptions{RequireApproval: true}), "pend1")
	if err := f.svc.Approve(f.ctx, f.admin, pending.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SetLocked(f.ctx, f.admin, pending.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Approve(f.ctx, f.admin, pending.ID); err == nil {
		t.Fatal("approving a locked account should fail")
	}
	want := []string{events.UserRegistered, events.UserApproved, events.UserLocked}
	var got []string
	for _, e := range pub.got {
		got = append(got, e.Topic)
		if e.UserID != pending.ID {
			t.Errorf("event %s for user %d, want %d", e.Topic, e.UserID, pending.ID)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("events = %v, want %v (failed changes must not publish)", got, want)
	}
}

func TestMembersDirectory(t *testing.T) {
	f := newFixture(t)
	f.user("anna_b")
	f.user("annaxb")
	locked := f.user("lockme")
	f.svc.SetLocked(f.ctx, f.admin, locked, true)
	f.register(f.invite(f.admin, InviteOptions{RequireApproval: true}), "pend1")

	all, total, err := f.svc.Members(f.ctx, "", 0, 100)
	if err != nil || total != 3 || len(all) != 3 {
		t.Fatalf("members = %v (%d), %v; want only the 3 active accounts", all, total, err)
	}
	got, total, _ := f.svc.Members(f.ctx, "anna_", 0, 10)
	if total != 1 || got[0].Username != "anna_b" {
		t.Errorf("literal prefix = %v", got)
	}
	page2, total, _ := f.svc.Members(f.ctx, "", 2, 2)
	if total != 3 || len(page2) != 1 || page2[0].Username != "sysadmin1" {
		t.Errorf("page 2 = %v", page2)
	}
}

func TestChangePassword(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	locked := f.user("lockme")
	if err := f.svc.SetLocked(f.ctx, f.admin, locked, true); err != nil {
		t.Fatal(err)
	}
	hash := func(id int64) string {
		t.Helper()
		var h string
		if err := f.db.QueryRowContext(f.ctx, `SELECT password_hash FROM users WHERE id = ?`, id).Scan(&h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	const newPassword = "a brand new long passphrase"
	tests := []struct {
		name string
		user int64
		pw   string
		want error
	}{
		{"too short", alice, "short", ErrPasswordPolicy},
		{"too long", alice, strings.Repeat("x", MaxPasswordLen+1), ErrPasswordPolicy},
		{"locked account", locked, newPassword, ErrNotFound},
		{"no such account", 9999, newPassword, ErrNotFound},
		{"changed", alice, newPassword, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := f.svc.ChangePassword(f.ctx, tt.user, tt.pw); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	for pw, want := range map[string]bool{newPassword: true, testPassword: false} {
		if ok, err := VerifyPassword(f.ctx, []byte(pw), hash(alice)); ok != want || err != nil {
			t.Errorf("password %q works = %v, %v; want %v", pw, ok, err, want)
		}
	}
	var detail string
	if err := f.db.QueryRowContext(f.ctx, `SELECT detail FROM audit_log WHERE action = ? AND actor_id = ?`, audit.PasswordChanged, alice).Scan(&detail); err != nil || detail != "" {
		t.Errorf("audit row: detail %q, %v", detail, err)
	}
	if n := f.auditCount(audit.PasswordChanged); n != 1 {
		t.Errorf("%d audit rows, want 1 (refusals are not changes)", n)
	}
}

// TestUsernamesManyRepeats: callers pass one ID per chat line or post, so
// a long log repeats a few authors far more often than SQLite allows bound
// parameters (32766); each is looked up once.
func TestUsernamesManyRepeats(t *testing.T) {
	f := newFixture(t)
	alice := f.user("alice")
	ids := make([]int64, 0, 40000)
	for i := range 40000 {
		ids = append(ids, []int64{f.admin, alice, 0, 999999}[i%4])
	}
	names, err := f.svc.Usernames(f.ctx, ids)
	if err != nil {
		t.Fatal(err)
	}
	if names[alice] != "alice" || names[f.admin] == "" || len(names) != 2 {
		t.Errorf("names = %v", names)
	}
}

// TestInvitesFollowCreator: an invite is checked against its creator as
// they are when it is used, so locking or demoting them, or a group
// gaining permissions they lack, stops their outstanding invites.
func TestInvitesFollowCreator(t *testing.T) {
	f := newFixture(t)
	vips, err := f.perms.CreateGroup(f.ctx, f.admin, "vips", "")
	if err != nil {
		t.Fatal(err)
	}
	modGroup, _ := f.perms.GroupByName(f.ctx, perm.GroupModerator)
	lockMe := f.user("mod1", perm.GroupModerator)
	demoteMe := f.user("mod2", perm.GroupModerator)
	leaveVips := f.user("mod3", perm.GroupModerator, "vips")
	memberGains := f.user("mod4", perm.GroupModerator)
	stays := f.user("mod5", perm.GroupModerator)
	codes := map[int64]string{
		lockMe:      f.invite(lockMe, InviteOptions{MaxUses: 2}),
		demoteMe:    f.invite(demoteMe, InviteOptions{}),
		leaveVips:   f.invite(leaveVips, InviteOptions{Groups: []string{"vips"}}),
		memberGains: f.invite(memberGains, InviteOptions{}), // into member
		stays:       f.invite(stays, InviteOptions{Groups: []string{perm.GroupModerator}}),
	}
	// Each creator changes; the last one does not.
	if err := f.svc.SetLocked(f.ctx, f.admin, lockMe, true); err != nil {
		t.Fatal(err)
	}
	if err := f.perms.RemoveMember(f.ctx, f.admin, modGroup.ID, demoteMe); err != nil {
		t.Fatal(err)
	}
	if err := f.perms.RemoveMember(f.ctx, f.admin, vips, leaveVips); err != nil {
		t.Fatal(err)
	}
	// member (which needs only its permissions, not membership) gains one
	// the moderators lack.
	memberGroup, _ := f.perms.GroupByName(f.ctx, perm.GroupMember)
	if err := f.perms.Grant(f.ctx, f.admin, memberGroup.ID, perm.AuditView); err != nil {
		t.Fatal(err)
	}
	line, _ := newKeyLine(t, "")
	tests := []struct {
		name    string
		creator int64
		want    error
	}{
		{"creator locked", lockMe, ErrInviteInvalid},
		{"creator lost core.invite.create", demoteMe, ErrInviteInvalid},
		{"creator left the group", leaveVips, ErrInviteInvalid},
		{"its group gained a permission the creator lacks", memberGains, ErrInviteInvalid},
		{"creator unchanged", stays, nil},
	}
	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := f.svc.CheckInvite(f.ctx, codes[tt.creator]); !errors.Is(err, tt.want) {
				t.Errorf("CheckInvite = %v, want %v", err, tt.want)
			}
			key, _ := newKeyLine(t, "")
			if tt.want != nil {
				key = line // never used: registration must fail first
			}
			if _, err := f.svc.Register(f.ctx, codes[tt.creator], Registration{Username: "newbie" + strconv.Itoa(i), Password: testPassword, PublicKey: key}); !errors.Is(err, tt.want) {
				t.Errorf("Register = %v, want %v", err, tt.want)
			}
		})
	}
	// Staff lists show which of them are on hold (the unchanged creator's
	// first invite was used above, so they make another).
	f.invite(stays, InviteOptions{Groups: []string{perm.GroupModerator}})
	list, err := f.svc.Invites(f.ctx, f.admin)
	if err != nil {
		t.Fatal(err)
	}
	states := map[int64]string{}
	for _, inv := range list { // newest first: the first seen per creator
		if _, seen := states[inv.CreatedBy]; !seen {
			states[inv.CreatedBy] = inv.State(f.clk.Now())
		}
	}
	if !strings.HasPrefix(states[lockMe], "on hold") || states[stays] != "usable" {
		t.Errorf("states: locked creator %q, unchanged creator %q", states[lockMe], states[stays])
	}

	// Unlocking the creator (once member no longer grants more than they
	// hold) makes their invite work again: the refusals spent nothing.
	if err := f.perms.Revoke(f.ctx, f.admin, memberGroup.ID, perm.AuditView); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.SetLocked(f.ctx, f.admin, lockMe, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CheckInvite(f.ctx, codes[lockMe]); err != nil {
		t.Errorf("after unlocking the creator: %v", err)
	}
}

// TestUserIDsNotReused: a rejected applicant's account row is deleted,
// but its ID is never given to a later account, so audit entries about it
// cannot be mistaken for the new account's.
func TestUserIDsNotReused(t *testing.T) {
	f := newFixture(t)
	pending := f.register(f.invite(f.admin, InviteOptions{RequireApproval: true}), "applicant").ID
	if err := f.svc.Reject(f.ctx, f.admin, pending); err != nil {
		t.Fatal(err)
	}
	next := f.user("newcomer")
	if next == pending || next != pending+1 {
		t.Errorf("next account got ID %d; the rejected one had %d", next, pending)
	}
	var about int
	f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE actor_id = ? OR (target_type = 'user' AND target_id = ?)`,
		pending, strconv.FormatInt(pending, 10)).Scan(&about)
	if about == 0 {
		t.Fatal("no audit entries about the rejected applicant to protect")
	}

	// An account inserted with an explicit ID moves the mark too.
	if _, err := f.db.ExecContext(f.ctx, `INSERT INTO users (id, username, password_hash, status, created_at) VALUES (500, 'imported', 'x', 'active', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(f.ctx, `DELETE FROM users WHERE id = 500`); err != nil {
		t.Fatal(err)
	}
	if id := f.user("after"); id != 501 {
		t.Errorf("after an explicit ID 500, next ID = %d, want 501", id)
	}
}
