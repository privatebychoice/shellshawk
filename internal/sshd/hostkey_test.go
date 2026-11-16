package sshd

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestLoadOrCreateHostKey(t *testing.T) {
	t.Run("creates then reloads the same key", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "host_ed25519")
		first, err := LoadOrCreateHostKey(path, quietLog())
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("new key permissions = %#o, want 0600", perm)
		}
		second, err := LoadOrCreateHostKey(path, quietLog())
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		if ssh.FingerprintSHA256(first.PublicKey()) != ssh.FingerprintSHA256(second.PublicKey()) {
			t.Error("reloaded key differs from created key")
		}
		if first.PublicKey().Type() != ssh.KeyAlgoED25519 {
			t.Errorf("key type = %s", first.PublicKey().Type())
		}
	})

	rsaPEM := func(t *testing.T) []byte {
		k, err := rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ssh.MarshalPrivateKey(k, "")
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(b)
	}

	tests := []struct {
		name    string
		content func(*testing.T) []byte
		perm    os.FileMode
	}{
		{"group/world readable refused", func(t *testing.T) []byte {
			p := filepath.Join(t.TempDir(), "k")
			if _, err := LoadOrCreateHostKey(p, quietLog()); err != nil {
				t.Fatal(err)
			}
			b, _ := os.ReadFile(p)
			return b
		}, 0o644},
		{"non-ed25519 refused", rsaPEM, 0o600},
		{"garbage refused", func(*testing.T) []byte { return []byte("not a key") }, 0o600},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "host_key")
			if err := os.WriteFile(path, tt.content(t), tt.perm); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tt.perm); err != nil { // bypass umask
				t.Fatal(err)
			}
			if _, err := LoadOrCreateHostKey(path, quietLog()); err == nil {
				t.Error("LoadOrCreateHostKey() error = nil, want error")
			}
		})
	}

	t.Run("missing directory is an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "no-such-dir", "host_key")
		if _, err := LoadOrCreateHostKey(path, quietLog()); err == nil {
			t.Error("error = nil, want error")
		}
	})
}
