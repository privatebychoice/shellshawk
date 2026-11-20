package auth

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/sshd"
)

// Password-login rate limits. Only password attempts are counted: SSH
// clients routinely offer several keys before the right one, and a key
// cannot be guessed. Invite logins are limited per IP only, so one abuser
// cannot block registration for everyone.
//
// A success never clears the per-IP count: it proves only that the
// client knew one password (or held one invite), so clearing it would let
// one address try 9 guesses, log in to an account of its own, and repeat.
// The per-account count is cleared when that account's password is right.
//
// An account is never blocked: that would let anyone keep a member who has
// lost their key from adding a new one. After userFailLimit wrong passwords
// in the window, each further attempt for the account waits before it is
// checked, 2 seconds doubling up to maxPasswordDelay, and the right
// password still works after the wait. Attempts are counted before the
// wait, so parallel connections all get the longer delays. Guessing from
// many addresses is bounded by the per-address limit and the connection
// limit (each delayed attempt holds a connection).
const (
	ipFailLimit      = 10
	userFailLimit    = 5
	failWindow       = 15 * time.Minute
	maxPasswordDelay = 30 * time.Second // 3 prompts fit in the 120 s handshake
	authDBTimeout    = 10 * time.Second
)

// passwordDelay is the wait before checking an account's n-th password
// attempt in the window.
func passwordDelay(n int) time.Duration {
	over := n - userFailLimit
	if over <= 0 {
		return 0
	}
	if over > 5 {
		return maxPasswordDelay
	}
	return min(2*time.Second<<(over-1), maxPasswordDelay)
}

// SSHAuthenticator implements sshd.Authenticator and sshd.LoginRecorder
// against the account database.
type SSHAuthenticator struct {
	svc    *Service
	ipLim  *Limiter
	usrLim *Limiter
	log    *slog.Logger
	sleep  func(time.Duration) // time.Sleep; tests record the delays
}

var (
	_ sshd.Authenticator = (*SSHAuthenticator)(nil)
	_ sshd.LoginRecorder = (*SSHAuthenticator)(nil)
)

// NewSSHAuthenticator returns an authenticator backed by svc.
func NewSSHAuthenticator(svc *Service) *SSHAuthenticator {
	a := &SSHAuthenticator{
		svc:    svc,
		ipLim:  NewLimiter(ipFailLimit, failWindow, svc.now),
		usrLim: NewLimiter(userFailLimit, failWindow, svc.now),
		log:    svc.log.With("component", "sshauth"),
		sleep:  time.Sleep,
	}
	// A new password starts with a clean count for its account (the
	// addresses' counts are kept: they are about who guessed, not what).
	svc.OnPasswordChanged(func(username string) { a.usrLim.Reset("user:" + username) })
	return a
}

// PublicKey maps a key to its account: active → member, pending → pending.
// Locked or unknown → denied.
func (a *SSHAuthenticator) PublicKey(c sshd.ConnInfo, key ssh.PublicKey) (sshd.Identity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), authDBTimeout)
	defer cancel()

	var userID int64
	var status, stored string
	err := a.svc.db.QueryRowContext(ctx, `
		SELECT u.id, u.status, k.public_key
		FROM user_keys k JOIN users u ON u.id = k.user_id
		WHERE k.fingerprint = ?`, ssh.FingerprintSHA256(key)).Scan(&userID, &status, &stored)
	if errors.Is(err, sql.ErrNoRows) {
		return sshd.Identity{}, sshd.ErrDenied
	}
	if err != nil {
		a.log.Error("key lookup failed", "conn_id", c.ConnID, "err", err)
		return sshd.Identity{}, sshd.ErrDenied
	}
	// Defence in depth: the full key must match, not just the fingerprint.
	storedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(stored))
	if err != nil || !bytes.Equal(storedKey.Marshal(), key.Marshal()) {
		a.log.Error("stored key does not match fingerprint", "conn_id", c.ConnID, "user_id", userID)
		return sshd.Identity{}, sshd.ErrDenied
	}

	uid := strconv.FormatInt(userID, 10)
	switch status {
	case StatusActive:
		return sshd.Identity{UserID: uid, Mode: sshd.ModeMember}, nil
	case StatusPending:
		return sshd.Identity{UserID: uid, Mode: sshd.ModePending}, nil
	default:
		a.log.Info("key login refused: account locked", "conn_id", c.ConnID, "user_id", userID)
		return sshd.Identity{}, sshd.ErrDenied
	}
}

// Password handles the two password logins: the invite user with an invite
// code (→ register), and an existing account's password (→ add key only).
func (a *SSHAuthenticator) Password(c sshd.ConnInfo, password []byte) (sshd.Identity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), authDBTimeout)
	defer cancel()

	// Attempts are counted before the (slow) check, so parallel
	// connections cannot all get past the limits; successes are given back.
	ipKey := IPLimitKey(c.RemoteIP)
	ipOK, ipLast := a.ipLim.Try(ipKey)
	if !ipOK {
		a.log.Info("password login rate-limited", "conn_id", c.ConnID, "scope", "ip")
		return sshd.Identity{}, sshd.ErrDenied
	}

	username := NormalizeUsername(c.User)
	if username == a.svc.inviteUser {
		code := string(password)
		if _, err := a.svc.CheckInvite(ctx, code); err != nil {
			if ipLast {
				a.svc.AuditLoginBlocked(ctx, BlockedAddress, 0, "ssh invite")
			}
			// The reason never contains the code: "invalid, expired, used
			// up or revoked", or that its creator can no longer issue it.
			a.log.Info("invite login refused", "conn_id", c.ConnID, "reason", err)
			return sshd.Identity{}, sshd.ErrDenied
		}
		a.ipLim.Forgive(ipKey)
		a.log.Info("invite login accepted", "conn_id", c.ConnID)
		return sshd.Identity{Mode: sshd.ModeRegister, InviteCode: code}, nil
	}

	userKey := "user:" + username
	n := a.usrLim.Attempt(userKey)
	if d := passwordDelay(n); d > 0 {
		a.log.Info("password login slowed", "conn_id", c.ConnID, "delay", d)
		a.sleep(d)
		// The database timeout starts after the wait.
		waited, cancelWaited := context.WithTimeout(context.Background(), authDBTimeout)
		defer cancelWaited()
		ctx = waited
	}

	var userID int64
	var status, hash string
	err := a.svc.db.QueryRowContext(ctx, `SELECT id, status, password_hash FROM users WHERE username = ?`, username).
		Scan(&userID, &status, &hash)
	exists := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		a.log.Error("user lookup failed", "conn_id", c.ConnID, "err", err)
		return sshd.Identity{}, sshd.ErrDenied
	}
	// An erased account has no password ("!erased", which no hash can
	// match). It is checked against the dummy hash like an unknown name,
	// so the time taken does not reveal tombstones and nothing is logged
	// as an error.
	erased := exists && strings.HasPrefix(hash, "!")
	if !exists || erased {
		hash = dummyHash // equalise timing so usernames cannot be probed
	}
	ok, err := VerifyPassword(ctx, password, hash)
	if err != nil {
		a.log.Error("password verification error", "conn_id", c.ConnID, "err", err)
		ok = false
	}
	if !ok || !exists || erased {
		if ipLast {
			a.svc.AuditLoginBlocked(ctx, BlockedAddress, 0, "ssh password")
		}
		if n == userFailLimit {
			var id int64
			if exists && !erased {
				id = userID
			}
			a.svc.AuditLoginSlowed(ctx, id, "ssh password")
		}
		a.log.Info("password login refused", "conn_id", c.ConnID)
		return sshd.Identity{}, sshd.ErrDenied
	}
	// The password was right: neither count keeps this attempt.
	a.ipLim.Forgive(ipKey)
	if status == StatusLocked {
		a.usrLim.Forgive(userKey)
		a.log.Info("password login refused: account locked", "conn_id", c.ConnID, "user_id", userID)
		return sshd.Identity{}, sshd.ErrDenied
	}
	a.usrLim.Reset(userKey)
	a.log.Info("password login accepted for key management", "conn_id", c.ConnID, "user_id", userID)
	return sshd.Identity{UserID: strconv.FormatInt(userID, 10), Mode: sshd.ModeAddKey}, nil
}

// IPLimitKey is the rate-limit key for a client address. An IPv6 client
// is counted by its /64 network, the block one site or customer normally
// gets, so changing the address within it does not reset the count; an
// IPv4 (or IPv4-mapped) client by its address.
func IPLimitKey(ip netip.Addr) string {
	ip = ip.Unmap()
	if ip.Is6() {
		if p, err := ip.Prefix(64); err == nil {
			return "ip6:" + p.String()
		}
	}
	return "ip:" + ip.String()
}

// RecordLogin stamps last-login times once a connection is fully
// authenticated. Registration logins have no account yet.
func (a *SSHAuthenticator) RecordLogin(ctx context.Context, id sshd.Identity) {
	if id.Mode == sshd.ModeRegister {
		return
	}
	userID, err := strconv.ParseInt(id.UserID, 10, 64)
	if err != nil {
		a.log.Error("record login: bad user id", "err", err)
		return
	}
	if err := a.svc.RecordLogin(ctx, userID, id.KeyFingerprint); err != nil {
		a.log.Error("record login failed", "user_id", userID, "err", err)
	}
}
