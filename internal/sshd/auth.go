package sshd

import (
	"context"
	"errors"
	"net/netip"

	"golang.org/x/crypto/ssh"
)

// Mode is what an authenticated SSH connection is allowed to do. Password
// logins never get ModeMember (docs/DESIGN.md §2.4, §6.1).
type Mode string

const (
	// ModeMember: public key login to an active account; full BBS access.
	ModeMember Mode = "member"
	// ModePending: public key login to an account awaiting approval; status
	// screen only.
	ModePending Mode = "pending"
	// ModeRegister: invite-code password login; registration wizard only.
	ModeRegister Mode = "register"
	// ModeAddKey: existing user's password login; add-a-public-key screen only.
	ModeAddKey Mode = "add-key"
)

func (m Mode) valid() bool {
	switch m {
	case ModeMember, ModePending, ModeRegister, ModeAddKey:
		return true
	}
	return false
}

// Identity is the result of a successful authentication.
type Identity struct {
	// UserID is the account ID. Empty for ModeRegister (no account yet).
	UserID string
	Mode   Mode
	// InviteCode is the code used to log in, for ModeRegister only. The
	// registration wizard passes it back to the account service, which
	// re-checks it when creating the account.
	InviteCode string
	// KeyFingerprint is the SHA256 fingerprint of the key that
	// authenticated, for key logins only.
	KeyFingerprint string
}

// ConnInfo is what an Authenticator may know about the connecting client.
type ConnInfo struct {
	User   string // SSH user name sent by the client
	ConnID string // random per-connection ID for log correlation
	// RemoteIP is for in-memory rate limiting only. It must never be
	// logged or stored (privacy; see README).
	RemoteIP netip.Addr
}

// Authenticator decides who may connect. Implemented by internal/auth
// (stage 3).
type Authenticator interface {
	// PublicKey is called with a key that already satisfies CheckUserKey.
	// x/crypto only grants access after the client proves possession of the
	// key, so implementations just look up which account owns it. It may be
	// called for keys the client never proves, so it must not record logins
	// or change state; see LoginRecorder.
	PublicKey(c ConnInfo, key ssh.PublicKey) (Identity, error)
	// Password must only ever return ModeRegister or ModeAddKey.
	Password(c ConnInfo, password []byte) (Identity, error)
}

// LoginRecorder is optionally implemented by an Authenticator. RecordLogin
// is called once per connection after authentication has fully completed.
type LoginRecorder interface {
	RecordLogin(ctx context.Context, id Identity)
}

// ErrDenied is returned by DenyAll.
var ErrDenied = errors.New("authentication denied")

// DenyAll rejects every login. It is used until account support exists, so
// the server can run (and its crypto policy be verified) with no way in.
type DenyAll struct{}

func (DenyAll) PublicKey(ConnInfo, ssh.PublicKey) (Identity, error) { return Identity{}, ErrDenied }
func (DenyAll) Password(ConnInfo, []byte) (Identity, error)         { return Identity{}, ErrDenied }

// Permissions extension keys carrying the Identity from the auth callbacks to
// the connection handler. They exist only server-side.
const (
	extUserID     = "shellshawk-user-id"
	extMode       = "shellshawk-mode"
	extInviteCode = "shellshawk-invite-code"
	extKeyFP      = "shellshawk-key-fp"
)

func identityToPermissions(id Identity) *ssh.Permissions {
	return &ssh.Permissions{Extensions: map[string]string{
		extUserID: id.UserID, extMode: string(id.Mode), extInviteCode: id.InviteCode, extKeyFP: id.KeyFingerprint,
	}}
}

func identityFromPermissions(p *ssh.Permissions) (Identity, bool) {
	if p == nil {
		return Identity{}, false
	}
	id := Identity{
		UserID: p.Extensions[extUserID], Mode: Mode(p.Extensions[extMode]),
		InviteCode: p.Extensions[extInviteCode], KeyFingerprint: p.Extensions[extKeyFP],
	}
	return id, id.Mode.valid()
}
