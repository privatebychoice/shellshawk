package privacy

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

const pw = "a long enough test passphrase"

type friends map[[2]int64]bool

func (f friends) IsFriend(_ context.Context, a, b int64) (bool, error) {
	return f[[2]int64{a, b}] || f[[2]int64{b, a}], nil
}

type fixture struct {
	ctx                      context.Context
	auth                     *auth.Service
	perms                    *perm.Service
	svc                      *Service
	now                      time.Time
	mu                       sync.Mutex
	admin, alice, bob, carol int64
}

func (f *fixture) clock() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now }

func setup(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "p.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f := &fixture{ctx: ctx, now: time.Now()}
	f.perms = perm.NewService(db, perm.NewRegistry(), nil, log)
	f.auth = auth.NewService(db, f.perms, "new", nil, log)
	f.svc = NewService(db, f.auth, f.perms, 14*24*time.Hour, f.clock, log)
	reg := func(code, name string) int64 {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		s, _ := ssh.NewSignerFromKey(priv)
		u, err := f.auth.Register(ctx, code, auth.Registration{Username: name, Password: pw,
			PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	code, _ := f.auth.CreateBootstrapInvite(ctx)
	f.admin = reg(code, "admin1")
	inv := func() string { c, _, _ := f.auth.CreateInvite(ctx, f.admin, auth.InviteOptions{}); return c }
	f.alice, f.bob, f.carol = reg(inv(), "alice"), reg(inv(), "bob"), reg(inv(), "carol")
	f.svc.SetFriends(friends{{f.alice, f.bob}: true})
	return f
}

func TestVisibility(t *testing.T) {
	f := setup(t)
	if err := f.svc.Update(f.ctx, f.alice, Profile{
		FullName: "Alice Example", Email: "alice@example.org", Phone: "+1 555 010 0123", Status: "Out walking",
		Visibility: map[Field]Level{FullName: Public, Email: Friends},
	}); err != nil {
		t.Fatal(err)
	}
	p, _ := f.svc.Get(f.ctx, f.alice)
	if p.Phone != "+15550100123" || p.Visibility[Phone] != NoOne || p.Visibility[Status] != Friends {
		t.Errorf("profile = %+v (phone normalised, untouched fields keep defaults)", p)
	}

	tests := []struct {
		name         string
		viewer       int64
		wantName     string
		wantEmail    string
		wantPhone    string
		wantStatus   string
		wantMessages bool
	}{
		{"self sees everything", f.alice, "Alice Example", "alice@example.org", "+15550100123", "Out walking", true},
		{"friend: public + friends fields", f.bob, "Alice Example", "alice@example.org", "", "Out walking", true},
		{"stranger: public only", f.carol, "Alice Example", "", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := f.svc.View(f.ctx, tt.viewer, f.alice)
			if err != nil {
				t.Fatal(err)
			}
			if v.FullName != tt.wantName || v.Email != tt.wantEmail || v.Phone != tt.wantPhone || v.Status != tt.wantStatus {
				t.Errorf("view = %+v", v)
			}
			if ok, _ := f.svc.Allows(f.ctx, tt.viewer, f.alice, Messages); ok != tt.wantMessages {
				t.Errorf("may message = %v, want %v", ok, tt.wantMessages)
			}
			if tt.viewer != f.alice && v.LastLogin != nil {
				t.Error("last login shown despite the No one default")
			}
		})
	}

	bad := []Profile{
		{FullName: strings.Repeat("x", MaxFullName+1)},
		{Status: "hi\x1b[2J"},
		{Phone: "12345"},
		{Email: "not an email"},
		{Visibility: map[Field]Level{"shoe_size": Public}},
		{Visibility: map[Field]Level{Email: "everyone"}},
	}
	for i, b := range bad {
		if err := f.svc.Update(f.ctx, f.alice, b); !errors.Is(err, ErrInvalid) {
			t.Errorf("bad profile %d accepted: %v", i, err)
		}
	}
}

func TestAdminEmailIsAudited(t *testing.T) {
	f := setup(t)
	f.svc.Update(f.ctx, f.alice, Profile{Email: "alice@example.org"})
	f.svc.Update(f.ctx, f.admin, Profile{Email: "admin@example.org"})
	// bob is support staff: core.users.manage and nothing else.
	support, err := f.perms.CreateGroup(f.ctx, f.admin, "support", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.perms.Grant(f.ctx, f.admin, support, perm.UsersManage); err != nil {
		t.Fatal(err)
	}
	if err := f.perms.AddMember(f.ctx, f.admin, support, f.bob); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name          string
		actor, target int64
		want          string // "" = refused
	}{
		{"a member", f.carol, f.alice, ""},
		{"staff, a member's", f.bob, f.alice, "alice@example.org"},
		{"staff, an administrator's (outranks them)", f.bob, f.admin, ""},
		{"an administrator", f.admin, f.alice, "alice@example.org"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			email, err := f.svc.AdminEmail(f.ctx, tt.actor, tt.target)
			if tt.want == "" && !errors.Is(err, perm.ErrForbidden) || tt.want != "" && (err != nil || email != tt.want) {
				t.Errorf("= %q, %v; want %q", email, err, tt.want)
			}
		})
	}
	var n int
	f.svc.db.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'admin.viewed.email'`).Scan(&n)
	if n != 2 {
		t.Errorf("audit entries = %d, want 2 (refusals are not views)", n)
	}
}

type recordingBus struct {
	got  []events.Event
	fail bool
}

func (b *recordingBus) Publish(_ context.Context, e events.Event) error {
	b.got = append(b.got, e)
	if b.fail {
		return errors.New("plugin failed")
	}
	return nil
}

func TestErasure(t *testing.T) {
	f := setup(t)
	f.svc.Update(f.ctx, f.alice, Profile{FullName: "Alice", Email: "alice@example.org"})
	e, err := f.svc.RequestErasure(f.ctx, f.alice, true)
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := f.auth.UserByID(f.ctx, f.alice); u.Status != auth.StatusLocked {
		t.Error("account not locked at once")
	}
	if !e.EraseAfter.Equal(f.now.Add(14 * 24 * time.Hour)) {
		t.Errorf("erase after = %v", e.EraseAfter)
	}
	if err := f.auth.SetLocked(f.ctx, f.admin, f.alice, false); !errors.Is(err, auth.ErrErasurePending) {
		t.Errorf("plain unlock during erasure err = %v", err)
	}

	bus := &recordingBus{}
	if n, _ := f.svc.RunDue(f.ctx, bus); n != 0 || len(bus.got) != 0 {
		t.Fatal("erased before the grace period ended")
	}
	f.mu.Lock()
	f.now = f.now.Add(15 * 24 * time.Hour)
	f.mu.Unlock()

	bus.fail = true
	if n, _ := f.svc.RunDue(f.ctx, bus); n != 0 {
		t.Error("erased although a plugin failed")
	}
	bus.fail = false
	n, err := f.svc.RunDue(f.ctx, bus)
	if err != nil || n != 1 {
		t.Fatalf("RunDue = %d, %v", n, err)
	}
	last := bus.got[len(bus.got)-1]
	if last.Topic != events.UserErased || last.UserID != f.alice || !last.DeleteContent {
		t.Errorf("event = %+v", last)
	}
	u, err := f.auth.UserByID(f.ctx, f.alice)
	if err != nil || !strings.HasPrefix(u.Username, auth.TombstonePrefix) || u.Email != "" || u.Status != auth.StatusLocked {
		t.Fatalf("tombstone = %+v, %v", u, err)
	}
	if keys, _ := f.auth.Keys(f.ctx, f.alice); len(keys) != 0 {
		t.Error("keys kept")
	}
	if p, _ := f.svc.Get(f.ctx, f.alice); p.FullName != "" {
		t.Error("profile kept")
	}
	if _, err := f.auth.UserByUsername(f.ctx, "alice"); !errors.Is(err, auth.ErrNotFound) {
		t.Error("old username still taken")
	}
	if n, _ := f.svc.RunDue(f.ctx, bus); n != 0 {
		t.Error("erased twice")
	}
	if err := auth.ValidateUsername(u.Username, "new"); !errors.Is(err, auth.ErrUsernameReserved) {
		t.Error("tombstone names can be registered")
	}
}

func TestErasureCancelAndLastAdmin(t *testing.T) {
	f := setup(t)
	if _, err := f.svc.RequestErasure(f.ctx, f.admin, false); !errors.Is(err, ErrLastAdminErase) {
		t.Errorf("sole admin erasure err = %v", err)
	}
	f.svc.RequestErasure(f.ctx, f.bob, false)
	if err := f.svc.CancelErasure(f.ctx, f.carol, f.bob); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member cancelling err = %v", err)
	}
	if err := f.svc.CancelErasure(f.ctx, f.admin, f.bob); err != nil {
		t.Fatal(err)
	}
	if u, _ := f.auth.UserByID(f.ctx, f.bob); u.Status != auth.StatusActive {
		t.Error("account not reactivated")
	}
	if _, ok, _ := f.svc.Erasure(f.ctx, f.bob); ok {
		t.Error("request not removed")
	}
	if err := f.svc.CancelErasure(f.ctx, f.admin, f.bob); !errors.Is(err, ErrNoRequest) {
		t.Errorf("second cancel err = %v", err)
	}
}

func TestExportAccount(t *testing.T) {
	f := setup(t)
	f.svc.Update(f.ctx, f.alice, Profile{FullName: "Alice", Email: "alice@example.org"})
	files, err := f.svc.ExportSource().Export(f.ctx, f.alice)
	if err != nil || len(files) != 1 {
		t.Fatalf("export = %v, %v", files, err)
	}
	s := string(files[0].Data)
	for _, want := range []string{`"username": "alice"`, `"full_name": "Alice"`, `"email": "alice@example.org"`, `"ssh_keys"`, `"groups"`} {
		if !strings.Contains(s, want) {
			t.Errorf("account.json missing %s", want)
		}
	}
	if strings.Contains(s, "argon2") {
		t.Error("password hash exported")
	}
}
