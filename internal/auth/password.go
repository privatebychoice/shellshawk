package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Password policy. A password is a single factor that can add an SSH key
// (and so reach the whole account), so the minimum follows NIST SP 800-63B-4
// for single-factor passwords. Length, not composition rules, is enforced.
const (
	MinPasswordLen = 15
	MaxPasswordLen = 256
)

// argon2id parameters: OWASP's recommended minimum (19 MiB, t=2, p=1). Memory
// is kept modest because many logins may hash concurrently; hashSlots bounds
// that concurrency so a login flood cannot exhaust memory.
const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
	hashSlots    = 4
)

var hashSem = make(chan struct{}, hashSlots)

// ErrPasswordPolicy is returned when a new password does not meet the policy.
var ErrPasswordPolicy = fmt.Errorf("password must be %d to %d characters", MinPasswordLen, MaxPasswordLen)

// ValidatePassword checks a new password against the policy.
func ValidatePassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if !utf8.ValidString(pw) || n < MinPasswordLen || n > MaxPasswordLen {
		return ErrPasswordPolicy
	}
	return nil
}

// HashPassword returns an argon2id hash in PHC string format.
func HashPassword(ctx context.Context, pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key, err := argonKey(ctx, []byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	if err != nil {
		return "", err
	}
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("auth: malformed password hash")

// VerifyPassword reports whether pw matches the PHC-encoded hash. Parameters
// are read from the hash, so stored hashes keep working if defaults change.
func VerifyPassword(ctx context.Context, pw []byte, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errBadHash
	}
	// Bound parameters so a tampered row cannot make verification hang.
	if m == 0 || m > 256*1024 || t == 0 || t > 10 || p == 0 || p > 8 {
		return false, errBadHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 64 {
		return false, errBadHash
	}
	got, err := argonKey(ctx, pw, salt, t, m, p, uint32(len(want)))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

func argonKey(ctx context.Context, pw, salt []byte, t, m uint32, p uint8, keyLen uint32) ([]byte, error) {
	select {
	case hashSem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-hashSem }()
	return argon2.IDKey(pw, salt, t, m, p, keyLen), nil
}

// dummyHash is verified against when an account does not exist, so a
// failed login takes the same time whether or not the username is real.
var dummyHash = func() string {
	h, err := HashPassword(context.Background(), "shellshawk-timing-equaliser")
	if err != nil {
		panic(err)
	}
	return h
}()
