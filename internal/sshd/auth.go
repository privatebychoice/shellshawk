package sshd

import (
	"errors"

	"golang.org/x/crypto/ssh"
)

// Mode is what an authenticated SSH connection is allowed to do. Password
// logins never get ModeMember (docs/DESIGN.md §2.4, §6.1).
type Mode string

const (
	// ModeMember: public key login to an existing account; full BBS access.
	ModeMember Mode = "member"
	// ModeRegister: invite-code password login; registration wizard only.
	ModeRegister Mode = "register"
	// ModeAddKey: existing user's password login; add-a-public-key screen only.
	ModeAddKey Mode = "add-key"
)

func (m Mode) valid() bool {
	switch m {
	case ModeMember, ModeRegister, ModeAddKey:
		return true
	}
	return false
}

// Identity is the result of a successful authentication.
type Identity struct {
	// UserID is the account ID. Empty for ModeRegister (no account yet).
	UserID string
	Mode   Mode
}

// ConnInfo is what an Authenticator may know about the connecting client.
// The client address is deliberately not included (privacy; see README).
type ConnInfo struct {
	User   string // SSH user name sent by the client
	ConnID string // random per-connection ID for log correlation
}

// Authenticator decides who may connect. Implemented by internal/auth
// (stage 3).
type Authenticator interface {
	// PublicKey is called with a key that already satisfies CheckUserKey.
	// x/crypto only grants access after the client proves possession of the
	// key, so implementations just look up which account owns it.
	PublicKey(c ConnInfo, key ssh.PublicKey) (Identity, error)
	// Password must only ever return ModeRegister or ModeAddKey.
	Password(c ConnInfo, password []byte) (Identity, error)
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
	extUserID = "shellshawk-user-id"
	extMode   = "shellshawk-mode"
)

func identityToPermissions(id Identity) *ssh.Permissions {
	return &ssh.Permissions{Extensions: map[string]string{extUserID: id.UserID, extMode: string(id.Mode)}}
}

func identityFromPermissions(p *ssh.Permissions) (Identity, bool) {
	if p == nil {
		return Identity{}, false
	}
	id := Identity{UserID: p.Extensions[extUserID], Mode: Mode(p.Extensions[extMode])}
	return id, id.Mode.valid()
}
