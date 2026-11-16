package bbs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/menu"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/prefs"
	"go.privatebychoice.com/shellshawk/internal/settings"
	"go.privatebychoice.com/shellshawk/internal/sshd"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

const testPassword = "a long enough test passphrase"

type env struct {
	addr    string
	hostKey ssh.PublicKey
	auth    *auth.Service
	perms   *perm.Service
	prefs   *prefs.Service
}

func startBBS(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "bbs.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cat, err := theme.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	ps := perm.NewService(db, perm.NewRegistry(), nil, log)
	as := auth.NewService(db, ps, "new", nil, log)
	pr := prefs.NewService(db, cat, nil)
	st := settings.NewService(db, nil, log)
	bus := events.New(log)
	as.SetPublisher(bus)
	reg, err := plugin.Load(ctx, plugin.Deps{DB: db, Perms: ps, Auth: as, Events: bus, Log: log}, &helloPlugin{})
	if err != nil {
		t.Fatal(err)
	}
	h := &Handler{Auth: as, Settings: st, Perms: ps, Prefs: pr, Menu: menu.NewService(db, ps, nil, log), Plugins: reg, Log: log}
	if err := h.Menu.Seed(ctx, h.MenuDefaults()); err != nil {
		t.Fatal(err)
	}

	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(hostPriv)
	srv, err := sshd.New(sshd.Config{
		HostKey: host, Auth: auth.NewSSHAuthenticator(as), Log: log,
		Handler: h,
	})
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})
	return &env{addr: l.Addr().String(), hostKey: host.PublicKey(), auth: as, perms: ps, prefs: pr}
}

func newUserKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// session logs in, opens a PTY shell, sends input and returns everything
// the server wrote once the session ends.
func (e *env) session(t *testing.T, user string, am ssh.AuthMethod, input string) string {
	t.Helper()
	c, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{am}, HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial as %s: %v", user, err)
	}
	defer c.Close()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out := &lockedBuf{}
	sess.Stdout = out
	stdin, _ := sess.StdinPipe()
	if err := sess.RequestPty("xterm-256color", 30, 100, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("session did not finish; output so far:\n%s", out.String())
	}
	return out.String()
}

func TestRegisterLineModeThenLogin(t *testing.T) {
	e := startBBS(t)
	code, err := e.auth.CreateBootstrapInvite(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	signer, keyLine := newUserKey(t)

	input := strings.Join([]string{
		"s",                    // screen reader mode
		"Alice",                // username (normalised to lowercase)
		"short",                // password too short -> re-asked
		testPassword,           // password
		"something else here!", // confirm mismatch -> re-asked after form check
		"",                     // email (skip)
		keyLine, ".",           // key, then end of multi-line input
		"laptop",     // key name
		testPassword, // confirm re-asked
		"",           // end-of-screen Enter on the welcome page
	}, "\r") + "\r"
	out := e.session(t, "new", ssh.Password(code), input)

	for _, want := range []string{
		"Screen: shellshawk - Create your account",
		"Error: Password must be at least 15 characters.",
		"Error: does not match the password",
		"Your account \"alice\" has been created.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("registration output missing %q\n---\n%s", want, out)
		}
	}
	if strings.Contains(out, testPassword) {
		t.Error("password was echoed")
	}
	if strings.Contains(out, "\x1b[?1049h") {
		t.Error("line mode switched to the alternate screen")
	}

	u, err := e.auth.UserByUsername(context.Background(), "alice")
	if err != nil || u.Status != auth.StatusActive {
		t.Fatalf("user = %+v, %v", u, err)
	}
	if ok, _ := e.perms.Has(context.Background(), u.ID, perm.Admin); !ok {
		t.Error("bootstrap registration did not make an administrator")
	}
	p, _ := e.prefs.Get(context.Background(), u.ID)
	if p.Profile != theme.ProfileAccessible {
		t.Errorf("screen reader choice not saved: %+v", p)
	}

	// Log in with the key: line mode main menu, then log out (item 8:
	// the test plugin's two items come before Log out).
	out = e.session(t, "alice", ssh.PublicKeys(signer), "8\r")
	for _, want := range []string{"Screen: shellshawk - Main menu", "Welcome, alice.", "5. Administration"} {
		if !strings.Contains(out, want) {
			t.Errorf("member output missing %q\n---\n%s", want, out)
		}
	}
	u, _ = e.auth.UserByID(context.Background(), u.ID)
	if u.LastLoginAt == nil {
		t.Error("key login not recorded")
	}
}

func TestRegisterFullScreenAndPendingAndAddKey(t *testing.T) {
	e := startBBS(t)
	ctx := context.Background()
	bootstrap, _ := e.auth.CreateBootstrapInvite(ctx)
	_, adminKey := newUserKey(t)
	admin, err := e.auth.Register(ctx, bootstrap, auth.Registration{Username: "sysadmin", Password: testPassword, PublicKey: adminKey})
	if err != nil {
		t.Fatal(err)
	}
	code, _, err := e.auth.CreateInvite(ctx, admin.ID, auth.InviteOptions{RequireApproval: true})
	if err != nil {
		t.Fatal(err)
	}
	signer, keyLine := newUserKey(t)

	// Full screen: Enter at the mode question, then Tab between fields;
	// the key is pasted with bracketed paste; Ctrl-S submits.
	input := "\r" +
		"bob99\t" + testPassword + "\t" + testPassword + "\t" + "bob@example.org\t" +
		"\x1b[200~" + keyLine + "\n\x1b[201~" + "\t" + "desktop" + "\x13" +
		"\r" // dismiss the welcome page
	out := e.session(t, "new", ssh.Password(code), input)
	if !strings.Contains(out, "\x1b[?1049h") || !strings.HasSuffix(out, "\x1b[?1049l") {
		t.Error("full-screen mode did not enter and leave the alternate screen")
	}
	if !strings.Contains(out, "needs to approve it") {
		t.Errorf("pending notice missing\n%q", out)
	}

	bob, err := e.auth.UserByUsername(ctx, "bob99")
	if err != nil || bob.Status != auth.StatusPending || bob.Email != "bob@example.org" {
		t.Fatalf("bob = %+v, %v", bob, err)
	}
	keys, _ := e.auth.Keys(ctx, bob.ID)
	if len(keys) != 1 || keys[0].Label != "desktop" {
		t.Errorf("keys = %+v", keys)
	}

	// Pending key login: status screen only.
	out = e.session(t, "bob99", ssh.PublicKeys(signer), "\r")
	if !strings.Contains(out, "waiting for approval") {
		t.Errorf("pending screen missing\n%q", out)
	}

	// Password login: add-key screen only.
	_, second := newUserKey(t)
	input = "\x1b[200~" + second + "\x1b[201~" + "\t" + "phone" + "\x13" + "\r"
	out = e.session(t, "bob99", ssh.Password(testPassword), input)
	if !strings.Contains(out, "Your key has been added") {
		t.Errorf("add-key confirmation missing\n%q", out)
	}
	keys, _ = e.auth.Keys(ctx, bob.ID)
	if len(keys) != 2 {
		t.Errorf("keys after add = %d, want 2", len(keys))
	}
}

func TestSettingsSwitchesToLineMode(t *testing.T) {
	e := startBBS(t)
	ctx := context.Background()
	bootstrap, _ := e.auth.CreateBootstrapInvite(ctx)
	signer, keyLine := newUserKey(t)
	u, err := e.auth.Register(ctx, bootstrap, auth.Registration{Username: "carol", Password: testPassword, PublicKey: keyLine})
	if err != nil {
		t.Fatal(err)
	}

	// Full screen main menu: 1 = Display settings. In the form, the first
	// field (terminal type) has the cursor on option 1; move down to option
	// 4 (screen reader) and select it with Space, then Ctrl-S. The
	// confirmation is then shown in line mode; Enter dismisses it, and in
	// the line-mode main menu, 8 logs out.
	input := "1" + "\x1b[B\x1b[B\x1b[B " + "\x13" + "\r" + "8\r"
	out := e.session(t, "carol", ssh.PublicKeys(signer), input)
	p, _ := e.prefs.Get(ctx, u.ID)
	if p.Profile != theme.ProfileAccessible {
		t.Fatalf("profile = %q\n%q", p.Profile, out)
	}
	if !strings.Contains(out, "Screen: shellshawk - Display settings") || !strings.Contains(out, "Your settings have been saved.") {
		t.Errorf("line mode confirmation missing\n%q", out)
	}
}

func TestMarkdownGuideLineMode(t *testing.T) {
	e := startBBS(t)
	ctx := context.Background()
	bootstrap, _ := e.auth.CreateBootstrapInvite(ctx)
	signer, keyLine := newUserKey(t)
	u, err := e.auth.Register(ctx, bootstrap, auth.Registration{Username: "dave", Password: testPassword, PublicKey: keyLine})
	if err != nil {
		t.Fatal(err)
	}
	p := prefs.Default()
	p.Profile, p.PageSize = theme.ProfileAccessible, 200
	if err := e.prefs.Set(ctx, u.ID, p); err != nil {
		t.Fatal(err)
	}
	// Main menu 4 = Markdown, 1 = guide, Enter to finish reading,
	// 2 = Try it: type markdown, end with ".", then "no" to stop, 3 = back, 8 = log out.
	input := strings.Join([]string{"4", "1", "", "2", "# Hi", "[x](javascript:alert(1))", ".", "", "1", "3", "8"}, "\r") + "\r"
	out := e.session(t, "dave", ssh.PublicKeys(signer), input)
	for _, want := range []string{
		"Heading level 1: Markdown guide",
		"Quote level 2:",
		"Code block start, language go, 2 lines:",
		"Link, grade ? Unclassified: https://example.org",
		"Section break.",
		"Screen: shellshawk - Preview",
		"Heading level 1: Hi",
		"x (link removed: unsupported address)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}

// helloPlugin is a test plugin: one item greets using a setting, the other
// panics, to prove a plugin bug cannot end the session.
type helloPlugin struct{ host *plugin.Host }

func (p *helloPlugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID: "hello", Name: "Hello", Version: "0.0.1",
		Settings: []plugin.Setting{{
			Field:   form.Field{Name: "greeting", Label: "Greeting", Kind: form.SingleLine, Required: true, MaxLen: 40},
			Default: "Hello",
		}},
		MenuItems: []plugin.MenuItem{
			{Key: "greet", Label: "Say hello", Run: func(ctx context.Context, s plugin.Session) error {
				g, err := p.host.Settings.Get(ctx, "greeting")
				if err != nil {
					return err
				}
				return tui.Message(ctx, s.UI(), s.Title("Hello"), g+" from a plugin.")
			}},
			{Key: "boom", Label: "Broken item", Run: func(context.Context, plugin.Session) error { panic("plugin bug") }},
		},
	}
}

func (p *helloPlugin) Init(_ context.Context, h *plugin.Host) error { p.host = h; return nil }

// accessibleAdmin registers a bootstrap admin who uses screen reader mode.
func (e *env) accessibleAdmin(t *testing.T, name string) ssh.Signer {
	t.Helper()
	ctx := context.Background()
	code, _ := e.auth.CreateBootstrapInvite(ctx)
	signer, keyLine := newUserKey(t)
	u, err := e.auth.Register(ctx, code, auth.Registration{Username: name, Password: testPassword, PublicKey: keyLine})
	if err != nil {
		t.Fatal(err)
	}
	p := prefs.Default()
	p.Profile, p.PageSize = theme.ProfileAccessible, 200
	if err := e.prefs.Set(ctx, u.ID, p); err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestPluginItemsAndRecovery(t *testing.T) {
	e := startBBS(t)
	signer := e.accessibleAdmin(t, "erin")
	// Main menu: 6 = Broken item, 7 = Say hello, 8 = Log out.
	out := e.session(t, "erin", ssh.PublicKeys(signer), "6\r\r7\r\r8\r")
	for _, want := range []string{"6. Broken item", "7. Say hello", "8. Log out",
		"Sorry, something went wrong", "Hello from a plugin."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if strings.Contains(out, "plugin bug") {
		t.Error("panic detail leaked to the member")
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}

func TestPluginSettingsAndMenuEditor(t *testing.T) {
	e := startBBS(t)
	signer := e.accessibleAdmin(t, "frank")
	// 5 Administration; 7 Plugin settings; 1 Hello; greeting "Howdy";
	// Enter to dismiss "Settings saved."; q back to main; 7 Say hello; Enter;
	// 5 Administration; 8 Menu editor; 8 Log out entry; 4 Delete; 2 Yes ->
	// protected message, Enter; q, q, then 8 Log out.
	input := strings.Join([]string{"5", "7", "1", "Howdy", "", "q", "7", "", "5", "8", "8", "4", "2", "", "q", "q", "8"}, "\r") + "\r"
	out := e.session(t, "frank", ssh.PublicKeys(signer), input)
	for _, want := range []string{"Settings saved.", "Howdy from a plugin.", "cannot be deleted"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}

func TestMemberDoesNotSeeAdministration(t *testing.T) {
	e := startBBS(t)
	ctx := context.Background()
	_ = e.accessibleAdmin(t, "gina")
	admin, _ := e.auth.UserByUsername(ctx, "gina")
	code, _, err := e.auth.CreateInvite(ctx, admin.ID, auth.InviteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	signer, keyLine := newUserKey(t)
	u, err := e.auth.Register(ctx, code, auth.Registration{Username: "henry", Password: testPassword, PublicKey: keyLine})
	if err != nil {
		t.Fatal(err)
	}
	p := prefs.Default()
	p.Profile = theme.ProfileAccessible
	e.prefs.Set(ctx, u.ID, p)
	out := e.session(t, "henry", ssh.PublicKeys(signer), "q\r")
	if strings.Contains(out, "Administration") {
		t.Errorf("member sees Administration:\n%s", out)
	}
	if !strings.Contains(out, "7. Log out") {
		t.Errorf("menu numbering unexpected:\n%s", out)
	}
}
