package auth

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/sshd"
)

func conn(user, ip string) sshd.ConnInfo {
	return sshd.ConnInfo{User: user, ConnID: "test", RemoteIP: netip.MustParseAddr(ip)}
}

func TestSSHPublicKey(t *testing.T) {
	f := newFixture(t)
	a := NewSSHAuthenticator(f.svc)

	activeLine, activeKey := newKeyLine(t, "")
	pendingLine, pendingKey := newKeyLine(t, "")
	lockedLine, lockedKey := newKeyLine(t, "")
	_, strangerKey := newKeyLine(t, "")

	reg := func(username, line string, opt InviteOptions) User {
		u, err := f.svc.Register(f.ctx, f.invite(f.admin, opt), Registration{Username: username, Password: testPassword, PublicKey: line})
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	active := reg("active", activeLine, InviteOptions{})
	pending := reg("pending", pendingLine, InviteOptions{RequireApproval: true})
	locked := reg("locked", lockedLine, InviteOptions{})
	if err := f.svc.SetLocked(f.ctx, f.admin, locked.ID, true); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		key      ssh.PublicKey
		wantMode sshd.Mode
		wantUser int64
		wantErr  bool
	}{
		{"active → member", activeKey, sshd.ModeMember, active.ID, false},
		{"pending → pending", pendingKey, sshd.ModePending, pending.ID, false},
		{"locked → denied", lockedKey, "", 0, true},
		{"unknown → denied", strangerKey, "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := a.PublicKey(conn("whatever", "192.0.2.1"), tt.key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if id.Mode != tt.wantMode || id.UserID != strconv.FormatInt(tt.wantUser, 10) {
				t.Errorf("identity = %+v", id)
			}
		})
	}
}

func TestSSHPassword(t *testing.T) {
	f := newFixture(t)
	a := NewSSHAuthenticator(f.svc)
	code := f.invite(f.admin, InviteOptions{})
	alice := f.user("alice")
	lockedUser := f.user("lockme")
	if err := f.svc.SetLocked(f.ctx, f.admin, lockedUser, true); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		user, pw string
		ip       string
		wantMode sshd.Mode
		wantUser int64
		wantErr  bool
	}{
		{"invite code → register", "NEW", code, "192.0.2.1", sshd.ModeRegister, 0, false},
		{"invite code, lowercase/no dashes", "new", NormalizeInviteCode(code), "192.0.2.1", sshd.ModeRegister, 0, false},
		{"bad invite code", "new", "WRONG-CODE", "192.0.2.1", "", 0, true},
		{"account password → add-key", "Alice", testPassword, "192.0.2.2", sshd.ModeAddKey, alice, false},
		{"wrong password", "alice", "not the right password", "192.0.2.2", "", 0, true},
		{"unknown user", "nobody99", testPassword, "192.0.2.2", "", 0, true},
		{"locked account", "lockme", testPassword, "192.0.2.3", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := a.Password(conn(tt.user, tt.ip), []byte(tt.pw))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if id.Mode != tt.wantMode {
				t.Errorf("mode = %s, want %s", id.Mode, tt.wantMode)
			}
			if tt.wantMode == sshd.ModeRegister && id.InviteCode != tt.pw {
				t.Errorf("invite code not carried: %+v", id)
			}
			if tt.wantMode == sshd.ModeAddKey && id.UserID != strconv.FormatInt(tt.wantUser, 10) {
				t.Errorf("user = %s", id.UserID)
			}
		})
	}
}

func TestSSHPasswordRateLimits(t *testing.T) {
	f := newFixture(t)
	a := NewSSHAuthenticator(f.svc)
	f.user("alice")

	// Per-account: after userFailLimit failures even the right password is
	// refused, from any IP, until the window passes.
	for i := range userFailLimit {
		a.Password(conn("alice", "192.0.2."+strconv.Itoa(10+i)), []byte("wrong password here"))
	}
	if _, err := a.Password(conn("alice", "192.0.2.99"), []byte(testPassword)); err == nil {
		t.Error("account not rate-limited after repeated failures")
	}
	f.clk.Advance(failWindow + time.Second)
	if _, err := a.Password(conn("alice", "192.0.2.99"), []byte(testPassword)); err != nil {
		t.Errorf("account still blocked after window: %v", err)
	}

	// Per-IP: invite guessing from one address is cut off; other addresses
	// can still register.
	code := f.invite(f.admin, InviteOptions{})
	for range ipFailLimit {
		a.Password(conn("new", "198.51.100.7"), []byte("GUESS"))
	}
	if _, err := a.Password(conn("new", "198.51.100.7"), []byte(code)); err == nil {
		t.Error("IP not rate-limited after repeated invite failures")
	}
	if _, err := a.Password(conn("new", "198.51.100.8"), []byte(code)); err != nil {
		t.Errorf("other IP blocked: %v", err)
	}
}

func TestRecordLogin(t *testing.T) {
	f := newFixture(t)
	a := NewSSHAuthenticator(f.svc)
	keys, _ := f.svc.Keys(f.ctx, f.admin)
	f.clk.Advance(time.Hour)
	a.RecordLogin(f.ctx, sshd.Identity{UserID: strconv.FormatInt(f.admin, 10), Mode: sshd.ModeMember, KeyFingerprint: keys[0].Fingerprint})

	u, _ := f.svc.UserByID(f.ctx, f.admin)
	if u.LastLoginAt == nil || !u.LastLoginAt.Equal(f.clk.Now()) {
		t.Errorf("last login = %v, want %v", u.LastLoginAt, f.clk.Now())
	}
	keys, _ = f.svc.Keys(f.ctx, f.admin)
	if keys[0].LastUsedAt == nil {
		t.Error("key last_used_at not set")
	}
	// Registration logins have no account and must be ignored.
	a.RecordLogin(f.ctx, sshd.Identity{Mode: sshd.ModeRegister, InviteCode: "x"})
}

func TestLimiter(t *testing.T) {
	clk := &clock{t: time.Unix(0, 0)}
	l := NewLimiter(2, time.Minute, clk.Now)
	if l.Blocked("k") {
		t.Fatal("blocked before any failure")
	}
	l.Fail("k")
	if l.Blocked("k") {
		t.Fatal("blocked after 1 of 2")
	}
	l.Fail("k")
	if !l.Blocked("k") {
		t.Fatal("not blocked at limit")
	}
	if l.Blocked("other") {
		t.Fatal("keys not independent")
	}
	clk.Advance(time.Minute)
	if l.Blocked("k") {
		t.Fatal("still blocked after window")
	}
	l.Fail("k")
	l.Fail("k")
	l.Reset("k")
	if l.Blocked("k") {
		t.Fatal("blocked after Reset")
	}
}
