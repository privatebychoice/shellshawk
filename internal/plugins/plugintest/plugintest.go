// Package plugintest helps test plugins against a real database and the core
// services. It is only imported by tests.
package plugintest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// Password is the password of every account the harness creates.
const Password = "a long enough test passphrase"

// Env is a loaded plugin environment.
type Env struct {
	t        *testing.T
	Ctx      context.Context
	DB       *sql.DB
	Auth     *auth.Service
	Perms    *perm.Service
	Events   *events.Bus
	Registry *plugin.Registry
	Admin    int64 // bootstrap administrator "admin1"
	Log      *slog.Logger
}

// New opens a fresh database, creates an administrator and loads plugins.
func New(t *testing.T, plugins ...plugin.Plugin) *Env {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "plugin.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ps := perm.NewService(db, perm.NewRegistry(), nil, log)
	as := auth.NewService(db, ps, "new", nil, log)
	bus := events.New(log)
	as.SetPublisher(bus)
	e := &Env{t: t, Ctx: ctx, DB: db, Auth: as, Perms: ps, Events: bus, Log: log}

	reg, err := plugin.Load(ctx, plugin.Deps{DB: db, Perms: ps, Auth: as, Events: bus, Log: log}, plugins...)
	if err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	e.Registry = reg

	code, err := as.CreateBootstrapInvite(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e.Admin = e.register(code, "admin1")
	return e
}

func keyLine(t *testing.T) string {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

func (e *Env) register(code, name string) int64 {
	e.t.Helper()
	u, err := e.Auth.Register(e.Ctx, code, auth.Registration{Username: name, Password: Password, PublicKey: keyLine(e.t)})
	if err != nil {
		e.t.Fatalf("register %s: %v", name, err)
	}
	return u.ID
}

// User creates an active member in the given groups ("member" if none).
func (e *Env) User(name string, groups ...string) int64 {
	e.t.Helper()
	code, _, err := e.Auth.CreateInvite(e.Ctx, e.Admin, auth.InviteOptions{Groups: groups})
	if err != nil {
		e.t.Fatal(err)
	}
	return e.register(code, name)
}
