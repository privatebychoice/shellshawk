package websess

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
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

func TestActivityListAndDelete(t *testing.T) {
	s, _, c, admin, alice := setup(t)
	ctx := context.Background()
	c.mu.Lock()
	c.t = c.t.Truncate(time.Second) // stored times are whole seconds
	c.mu.Unlock()
	start := c.now()
	tok, sess, _ := s.Create(ctx, alice)
	other, _, _ := s.Create(ctx, admin)
	if len(sess.ID) != 18 {
		t.Errorf("public ID = %q", sess.ID)
	}
	if i, _ := s.Get(ctx, sess.ID); !i.LastSeen.Equal(start) {
		t.Errorf("last seen at login = %v, want %v", i.LastSeen, start)
	}

	// Each step uses the session after advancing the clock; activity is
	// written at most once a minute.
	steps := []struct {
		advance, wantSeen time.Duration // wantSeen: last seen, after start
	}{
		{30 * time.Second, 0},
		{30 * time.Second, time.Minute},
		{59 * time.Second, time.Minute},
		{time.Second, 2 * time.Minute},
	}
	for n, st := range steps {
		c.add(st.advance)
		if _, err := s.Lookup(ctx, tok); err != nil {
			t.Fatal(err)
		}
		i, err := s.Get(ctx, sess.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got := i.LastSeen.Sub(start); got != st.wantSeen {
			t.Errorf("step %d: last seen = start+%v, want start+%v", n, got, st.wantSeen)
		}
	}

	// Both sessions were created in the same second, so their order in the
	// list depends on their random public IDs.
	all, err := s.List(ctx)
	users := map[string]int64{}
	for _, i := range all {
		users[i.ID] = i.UserID
	}
	if err != nil || len(all) != 2 || users[sess.ID] != alice || !slices.Contains(slices.Collect(maps.Values(users)), admin) {
		t.Fatalf("List = %+v, %v", all, err)
	}
	if err := s.DeleteByID(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteByID(ctx, sess.ID); !errors.Is(err, ErrNoSession) {
		t.Errorf("second delete err = %v", err)
	}
	if _, err := s.Lookup(ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Error("deleted session still valid")
	}
	if _, err := s.Lookup(ctx, other); err != nil {
		t.Errorf("other session ended: %v", err)
	}
	c.add(SessionTTL)
	if all, _ := s.List(ctx); len(all) != 0 {
		t.Errorf("expired sessions listed: %+v", all)
	}
}

// TestErasureRequestClearsSessions: an erasure request locks the account,
// so its web sessions and login code end as for a lock.
func TestErasureRequestClearsSessions(t *testing.T) {
	s, _, _, admin, alice := setup(t)
	ctx := context.Background()
	bus := events.New(slog.New(slog.DiscardHandler))
	s.Subscribe(bus)
	tok, _, _ := s.Create(ctx, alice)
	adminTok, _, _ := s.Create(ctx, admin)
	code, _, _ := s.NewCode(ctx, alice)

	if err := bus.Publish(ctx, events.Event{Topic: events.ErasureRequested, UserID: alice, Actor: alice}); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteUser(ctx, alice); n != 0 || err != nil {
		t.Errorf("sessions left after the request: %d, %v", n, err)
	}
	if _, err := s.Lookup(ctx, tok); !errors.Is(err, ErrNoSession) {
		t.Error("session still valid")
	}
	if _, err := s.Redeem(ctx, "alice", code); !errors.Is(err, ErrInvalidCode) {
		t.Error("login code still works")
	}
	if _, err := s.Lookup(ctx, adminTok); err != nil {
		t.Errorf("another member's session ended: %v", err)
	}
}

func TestVoidCode(t *testing.T) {
	s, _, _, admin, alice := setup(t)
	ctx := context.Background()
	code, _, _ := s.NewCode(ctx, alice)
	adminCode, _, _ := s.NewCode(ctx, admin)
	if ok, err := s.VoidCode(ctx, "alice"); !ok || err != nil {
		t.Fatalf("VoidCode = %v, %v", ok, err)
	}
	if _, err := s.Redeem(ctx, "alice", code); !errors.Is(err, ErrInvalidCode) {
		t.Error("a voided code still works")
	}
	if ok, _ := s.VoidCode(ctx, "alice"); ok {
		t.Error("voided a code that was not there")
	}
	if ok, err := s.VoidCode(ctx, "nobody"); ok || err != nil {
		t.Errorf("unknown username = %v, %v", ok, err)
	}
	if _, err := s.Redeem(ctx, "admin1", adminCode); err != nil {
		t.Errorf("another member's code was voided: %v", err)
	}
	fresh, _, _ := s.NewCode(ctx, alice)
	if id, err := s.Redeem(ctx, "alice", fresh); err != nil || id != alice {
		t.Errorf("a new code after voiding = %d, %v", id, err)
	}
}

// TestRedeemUnknownUsername: an unknown username goes through the same code
// lookup as a known one (so timing does not reveal whether it exists), and
// is refused the same way: a real code typed with either is refused and
// left for its owner (the refusal rolls back).
func TestRedeemUnknownUsername(t *testing.T) {
	s, _, _, _, alice := setup(t)
	ctx := context.Background()
	for _, name := range []string{"nobody", "admin1"} {
		code, _, _ := s.NewCode(ctx, alice)
		if _, err := s.Redeem(ctx, name, code); !errors.Is(err, ErrInvalidCode) {
			t.Errorf("%s with alice's code = %v", name, err)
		}
		if id, err := s.Redeem(ctx, "alice", code); err != nil || id != alice {
			t.Errorf("after %q tried it, alice's code = %d, %v", name, id, err)
		}
	}
}
