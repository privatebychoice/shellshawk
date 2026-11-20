package auth

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/audit"
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
	if l.Fail("k") {
		t.Fatal("first failure reported as the start of a block")
	}
	if l.Blocked("k") {
		t.Fatal("blocked after 1 of 2")
	}
	if !l.Fail("k") {
		t.Fatal("reaching the limit not reported")
	}
	if !l.Blocked("k") {
		t.Fatal("not blocked at limit")
	}
	if l.Fail("k") {
		t.Fatal("a failure while blocked reported as a new block")
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

// TestSSHIPLimitNotResetBySuccess: logging in successfully (with a
// password or an invite) does not clear the per-IP failure count, so one
// address cannot spray guesses by logging in to its own account between
// rounds; and IPv6 clients are counted per /64.
func TestSSHIPLimitNotResetBySuccess(t *testing.T) {
	tests := []struct {
		name      string
		ip, other string // other: an address in the same limit bucket
		success   func(f *fixture, a *SSHAuthenticator, ip string) error
	}{
		{"password login", "192.0.2.50", "192.0.2.50", func(f *fixture, a *SSHAuthenticator, ip string) error {
			_, err := a.Password(conn("own", ip), []byte(testPassword))
			return err
		}},
		{"invite login", "192.0.2.51", "192.0.2.51", func(f *fixture, a *SSHAuthenticator, ip string) error {
			_, err := a.Password(conn("new", ip), []byte(f.invite(f.admin, InviteOptions{})))
			return err
		}},
		{"IPv6, same /64", "2001:db8:1:2::10", "2001:db8:1:2:ffff::99", func(f *fixture, a *SSHAuthenticator, ip string) error {
			_, err := a.Password(conn("own", ip), []byte(testPassword))
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			a := NewSSHAuthenticator(f.svc)
			f.user("own")
			for i := range ipFailLimit - 1 {
				a.Password(conn("victim"+strconv.Itoa(i), tt.ip), []byte("wrong password here"))
			}
			if err := tt.success(f, a, tt.ip); err != nil {
				t.Fatalf("own login refused: %v", err)
			}
			// One more failure reaches the limit; then even a right
			// password from the same bucket is refused.
			a.Password(conn("victim", tt.other), []byte("wrong password here"))
			if _, err := a.Password(conn("own", tt.other), []byte(testPassword)); err == nil {
				t.Error("the success reset the per-IP count")
			}
		})
	}
}

func TestIPLimitKey(t *testing.T) {
	tests := []struct{ ip, want string }{
		{"192.0.2.7", "ip:192.0.2.7"},
		{"::ffff:192.0.2.7", "ip:192.0.2.7"},
		{"2001:db8:1:2:3:4:5:6", "ip6:2001:db8:1:2::/64"},
		{"2001:db8:1:2::", "ip6:2001:db8:1:2::/64"},
		{"2001:db8:1:3::1", "ip6:2001:db8:1:3::/64"},
	}
	for _, tt := range tests {
		if got := IPLimitKey(netip.MustParseAddr(tt.ip)); got != tt.want {
			t.Errorf("IPLimitKey(%s) = %q, want %q", tt.ip, got, tt.want)
		}
	}
}

// TestLoginBlocksAudited: reaching a login failure limit writes one audit
// row per block (not per attempt), naming the account but never an
// address.
func TestLoginBlocksAudited(t *testing.T) {
	f := newFixture(t)
	a := NewSSHAuthenticator(f.svc)
	alice := f.user("alice")
	rows := func() []audit.Entry {
		t.Helper()
		r, err := f.db.QueryContext(f.ctx, `SELECT target_type, target_id, detail FROM audit_log WHERE action = ? ORDER BY id`, audit.LoginBlocked)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		var out []audit.Entry
		for r.Next() {
			var e audit.Entry
			var target string
			r.Scan(&e.TargetType, &target, &e.Detail)
			e.TargetID, _ = strconv.ParseInt(target, 10, 64)
			out = append(out, e)
		}
		return out
	}
	// Twice the account limit, from addresses that never reach theirs.
	for i := range 2 * userFailLimit {
		a.Password(conn("alice", "192.0.2."+strconv.Itoa(10+i)), []byte("wrong password here"))
	}
	// Twice the address limit from one address, against unknown names.
	for i := range 2 * ipFailLimit {
		a.Password(conn("ghost"+strconv.Itoa(i), "198.51.100.9"), []byte("wrong password here"))
	}
	want := []audit.Entry{
		{TargetType: BlockedAccount, TargetID: alice, Detail: "ssh password"},
		{TargetType: BlockedAddress, Detail: "ssh password"},
	}
	got := rows()
	if len(got) != len(want) {
		t.Fatalf("audit rows = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	var leaked int
	f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE detail LIKE '%198.51.100%' OR target_id LIKE '%198.51.100%' OR detail LIKE '%ghost%'`).Scan(&leaked)
	if leaked != 0 {
		t.Error("an address or a typed name reached the audit log")
	}
}
