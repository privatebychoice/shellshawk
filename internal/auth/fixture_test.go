package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

const testInviteUser = "new"

// clock is a settable time source shared by the services under test.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	t     *testing.T
	ctx   context.Context
	db    *sql.DB
	clk   *clock
	perms *perm.Service
	svc   *Service
	admin int64 // bootstrap administrator
}

// newFixture returns services on a fresh database with a bootstrap admin.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := newEmptyFixture(t)
	code, err := f.svc.CreateBootstrapInvite(f.ctx)
	if err != nil {
		t.Fatalf("bootstrap invite: %v", err)
	}
	f.admin = f.register(code, "sysadmin1").ID
	return f
}

// newEmptyFixture returns services on a fresh database with no accounts.
func newEmptyFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clk := &clock{t: time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)}
	ps := perm.NewService(db, perm.NewRegistry(), clk.Now, log)
	return &fixture{t: t, ctx: ctx, db: db, clk: clk, perms: ps, svc: NewService(db, ps, testInviteUser, clk.Now, log)}
}

// newKeyLine returns a fresh Ed25519 authorized_keys line.
func newKeyLine(t *testing.T, comment string) (string, ssh.PublicKey) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sk)))
	if comment != "" {
		line += " " + comment
	}
	return line, sk
}

func rsaKeyLine(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sk)))
}

const testPassword = "correct horse battery staple"

// register registers username with code and a fresh key, failing the test
// on error.
func (f *fixture) register(code, username string) User {
	f.t.Helper()
	line, _ := newKeyLine(f.t, "")
	u, err := f.svc.Register(f.ctx, code, Registration{Username: username, Password: testPassword, PublicKey: line})
	if err != nil {
		f.t.Fatalf("Register(%s): %v", username, err)
	}
	return u
}

// invite creates an invite as actor, failing the test on error.
func (f *fixture) invite(actor int64, opt InviteOptions) string {
	f.t.Helper()
	code, _, err := f.svc.CreateInvite(f.ctx, actor, opt)
	if err != nil {
		f.t.Fatalf("CreateInvite: %v", err)
	}
	return code
}

// user creates an active account in the given groups via an admin invite.
func (f *fixture) user(username string, groups ...string) int64 {
	f.t.Helper()
	return f.register(f.invite(f.admin, InviteOptions{Groups: groups}), username).ID
}

func (f *fixture) auditCount(action string) int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRowContext(f.ctx, `SELECT count(*) FROM audit_log WHERE action = ?`, action).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}
