package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"

	"golang.org/x/crypto/ssh"
)

// LoadOrCreateHostKey returns the Ed25519 host key stored at path, generating
// and saving a new one if the file does not exist.
//
// An existing key is refused if group or others can access it, or if it is
// not Ed25519.
func LoadOrCreateHostKey(path string, log *slog.Logger) (ssh.Signer, error) {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return createHostKey(path, log)
	case err != nil:
		return nil, fmt.Errorf("sshd: host key: %w", err)
	}

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("sshd: host key %s has permissions %#o; must not be accessible by group or others (chmod 600)", path, perm)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sshd: read host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		return nil, fmt.Errorf("sshd: parse host key %s: %w", path, err)
	}
	if t := signer.PublicKey().Type(); t != ssh.KeyAlgoED25519 {
		return nil, fmt.Errorf("sshd: host key %s is %s; only %s is supported", path, t, ssh.KeyAlgoED25519)
	}
	log.Info("host key loaded", "path", path, "fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))
	return signer, nil
}

func createHostKey(path string, log *slog.Logger) (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshd: generate host key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("sshd: encode host key: %w", err)
	}
	// O_EXCL: never overwrite a key that appeared since the Stat above.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, fmt.Errorf("sshd: create host key: %w", err)
	}
	if err := pem.Encode(f, block); err != nil {
		f.Close()
		os.Remove(path)
		return nil, fmt.Errorf("sshd: write host key: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("sshd: write host key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("sshd: host key signer: %w", err)
	}
	log.Warn("generated new host key", "path", path, "fingerprint", ssh.FingerprintSHA256(signer.PublicKey()))
	return signer, nil
}
