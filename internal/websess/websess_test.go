package websess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }

func setup(t *testing.T) (*Service, *auth.Service, *clock, int64, int64) {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "w.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ps := perm.NewService(db, perm.NewRegistry(), nil, log)
	as := auth.NewService(db, ps, "new", nil, log)
	reg := func(code, name string) int64 {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		s, _ := ssh.NewSignerFromKey(priv)
		u, err := as.Register(ctx, code, auth.Registration{Username: name, Password: "a long enough test passphrase",
			PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	code, _ := as.CreateBootstrapInvite(ctx)
	admin := reg(code, "admin1")
	inv, _, _ := as.CreateInvite(ctx, admin, auth.InviteOptions{})
	alice := reg(inv, "alice")
	c := &clock{t: time.Now()}
	return NewService(db, as, c.now, log), as, c, admin, alice
}

func TestCodes(t *testing.T) {
	s, _, c, admin, alice := setup(t)
	ctx := context.Background()
	code, exp, err := s.NewCode(ctx, alice)
	if err != nil || len(code) != 9 || code[4] != '-' || !exp.Equal(c.now().Add(CodeTTL)) {
		t.Fatalf("NewCode = %q, %v, %v", code, exp, err)
	}
	if _, err := s.Redeem(ctx, "admin1", code); !errors.Is(err, ErrInvalidCode) {
		t.Errorf("code redeemed for another member err = %v", err)
	}
	// The failed attempt above consumed nothing for alice? It did consume
	// the code (any use burns it), so issue a new one.
	code, _, _ = s.NewCode(ctx, alice)
	uid, err := s.Redeem(ctx, "ALICE", strings.ToLower(strings.ReplaceAll(code, "-", " ")))
	if err != nil || uid != alice {
		t.Fatalf("Redeem = %d, %v", uid, err)
	}
	if _, err := s.Redeem(ctx, "alice", code); !errors.Is(err, ErrInvalidCode) {
		t.Error("code worked twice")
	}

	old, _, _ := s.NewCode(ctx, alice)
	newer, _, _ := s.NewCode(ctx, alice)
	if _, err := s.Redeem(ctx, "alice", old); !errors.Is(err, ErrInvalidCode) {
		t.Error("an earlier code survived a new one")
	}
	c.add(CodeTTL + time.Second)
	if _, err := s.Redeem(ctx, "alice", newer); !errors.Is(err, ErrInvalidCode) {
		t.Error("expired code accepted")
	}
	_ = admin
}

func TestSessions(t *testing.T) {
	s, as, c, admin, alice := setup(t)
	ctx := context.Background()
	tok, sess, err := s.Create(ctx, alice)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(ctx, tok)
	if err != nil || got.UserID != alice || got.CSRF != sess.CSRF {
		t.Fatalf("Lookup = %+v, %v", got, err)
	}
	if !CheckCSRF(got, sess.CSRF) || CheckCSRF(got, "") || CheckCSRF(got, "wrong") {
		t.Error("CSRF check wrong")
	}
	if _, err := s.Lookup(ctx, tok+"x"); !errors.Is(err, ErrNoSession) {
		t.Error("tampered token accepted")
	}
	// Locking the account ends its web sessions at once.
	as.SetLocked(ctx, admin, alice, true)
	if _, err := s.Lookup(ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Error("locked account's session still valid")
	}
	as.SetLocked(ctx, admin, alice, false)
	c.add(SessionTTL)
	if _, err := s.Lookup(ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Error("expired session valid")
	}
	tok2, _, _ := s.Create(ctx, alice)
	s.Delete(ctx, tok2)
	if _, err := s.Lookup(ctx, tok2); !errors.Is(err, ErrNoSession) {
		t.Error("deleted session valid")
	}
}

func TestLockClearsSessions(t *testing.T) {
	s, as, _, admin, alice := setup(t)
	ctx := context.Background()
	bus := events.New(slog.New(slog.DiscardHandler))
	as.SetPublisher(bus)
	s.Subscribe(bus)

	tok1, _, _ := s.Create(ctx, alice)
	tok2, _, _ := s.Create(ctx, alice)
	adminTok, _, _ := s.Create(ctx, admin)
	code, _, _ := s.NewCode(ctx, alice)

	if err := as.SetLocked(ctx, admin, alice, true); err != nil {
		t.Fatal(err)
	}
	if err := as.SetLocked(ctx, admin, alice, false); err != nil {
		t.Fatal(err)
	}
	// After the unlock, nothing from before the lock works again.
	for _, tok := range []string{tok1, tok2} {
		if _, err := s.Lookup(ctx, tok); !errors.Is(err, ErrNoSession) {
			t.Error("a session from before the lock came back after the unlock")
		}
	}
	if _, err := s.Redeem(ctx, "alice", code); !errors.Is(err, ErrInvalidCode) {
		t.Error("a login code from before the lock still works")
	}
	if _, err := s.Lookup(ctx, adminTok); err != nil {
		t.Errorf("another member's session ended: %v", err)
	}
	// Logging in afresh works.
	if tok, _, err := s.Create(ctx, alice); err != nil {
		t.Fatal(err)
	} else if _, err := s.Lookup(ctx, tok); err != nil {
		t.Errorf("new session after unlock: %v", err)
	}
}
