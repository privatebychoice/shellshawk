package sshd

import (
	"crypto/rsa"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Crypto policy (docs/DESIGN.md §2.3). Lists are set explicitly instead of
// relying on x/crypto defaults, so a library upgrade can never widen them.
var (
	// KeyExchanges: post-quantum hybrid first, then X25519. x/crypto adds the
	// curve25519-sha256@libssh.org alias automatically.
	KeyExchanges = []string{
		ssh.KeyExchangeMLKEM768X25519,
		ssh.KeyExchangeCurve25519,
	}

	// Ciphers: AEAD only.
	Ciphers = []string{
		ssh.CipherChaCha20Poly1305,
		ssh.CipherAES256GCM,
		ssh.CipherAES128GCM,
	}

	// MACs are unused with AEAD ciphers but must be non-empty for
	// negotiation; only encrypt-then-MAC SHA-2 variants are offered.
	MACs = []string{
		ssh.HMACSHA256ETM,
		ssh.HMACSHA512ETM,
	}

	// UserSignatureAlgorithms are the signature algorithms accepted for
	// public key authentication. "ssh-rsa" (SHA-1) is excluded.
	UserSignatureAlgorithms = []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoSKED25519,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoSKECDSA256,
		ssh.KeyAlgoRSASHA512,
		ssh.KeyAlgoRSASHA256,
	}
)

// MinRSABits is the smallest RSA modulus accepted for user keys.
const MinRSABits = 3072

// allowedUserKeyTypes are the accepted user key types (as reported by
// ssh.PublicKey.Type). Certificates are not accepted.
var allowedUserKeyTypes = map[string]bool{
	ssh.KeyAlgoED25519:    true,
	ssh.KeyAlgoSKED25519:  true,
	ssh.KeyAlgoECDSA256:   true,
	ssh.KeyAlgoSKECDSA256: true,
	ssh.KeyAlgoRSA:        true, // key type only; SHA-1 signatures are refused above
}

// CheckUserKey reports whether key meets the user key policy. It is used both
// during authentication and when a user adds a key to their account.
func CheckUserKey(key ssh.PublicKey) error {
	t := key.Type()
	if !allowedUserKeyTypes[t] {
		return fmt.Errorf("key type %q is not allowed", t)
	}
	if t != ssh.KeyAlgoRSA {
		return nil
	}
	ck, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("cannot inspect RSA key")
	}
	rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("cannot inspect RSA key")
	}
	if bits := rk.N.BitLen(); bits < MinRSABits {
		return fmt.Errorf("RSA key is %d bits; at least %d required", bits, MinRSABits)
	}
	return nil
}
