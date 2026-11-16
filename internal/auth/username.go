package auth

import (
	"errors"
	"regexp"
	"strings"
)

// Usernames: 3–32 characters, lowercase letters, digits, '_' and '-',
// starting with a letter. Stored lowercase; uniqueness is case-insensitive.
var usernamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,31}$`)

// reservedUsernames cannot be registered: they would impersonate staff or
// system roles, or collide with the invite login name.
var reservedUsernames = map[string]bool{
	"admin": true, "administrator": true, "root": true, "sysop": true, "system": true,
	"moderator": true, "mod": true, "staff": true, "support": true, "help": true,
	"shellshawk": true, "new": true, "guest": true, "anonymous": true, "nobody": true,
	"invite": true, "register": true, "everyone": true, "all": true,
}

// TombstonePrefix starts the username an erased account is given, so it
// cannot be registered.
const TombstonePrefix = "former-"

// ErrUsernameInvalid and ErrUsernameReserved describe a rejected username.
var (
	ErrUsernameInvalid  = errors.New("username must be 3-32 characters: lowercase letters, digits, '_' or '-', starting with a letter")
	ErrUsernameReserved = errors.New("that username is reserved")
)

// NormalizeUsername lowercases and trims a username.
func NormalizeUsername(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

// ValidateUsername checks a normalized username. inviteUser (the configured
// registration login name) is also reserved.
func ValidateUsername(u, inviteUser string) error {
	if !usernamePattern.MatchString(u) {
		return ErrUsernameInvalid
	}
	if reservedUsernames[u] || u == NormalizeUsername(inviteUser) || strings.HasPrefix(u, TombstonePrefix) {
		return ErrUsernameReserved
	}
	return nil
}
