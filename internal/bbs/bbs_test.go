package bbs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/menu"
	"go.privatebychoice.com/shellshawk/internal/notify"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/chat"
	"go.privatebychoice.com/shellshawk/internal/plugins/conferences"
	"go.privatebychoice.com/shellshawk/internal/plugins/contacts"
	"go.privatebychoice.com/shellshawk/internal/plugins/messages"
	"go.privatebychoice.com/shellshawk/internal/plugins/motd"
	"go.privatebychoice.com/shellshawk/internal/plugins/polls"
	"go.privatebychoice.com/shellshawk/internal/plugins/wall"
	"go.privatebychoice.com/shellshawk/internal/prefs"
	"go.privatebychoice.com/shellshawk/internal/presence"
	"go.privatebychoice.com/shellshawk/internal/privacy"
	"go.privatebychoice.com/shellshawk/internal/sessions"
	"go.privatebychoice.com/shellshawk/internal/settings"
	"go.privatebychoice.com/shellshawk/internal/sshd"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

const testPassword = "a long enough test passphrase"

type env struct {
	addr    string
	hostKey ssh.PublicKey
	auth    *auth.Service
	perms   *perm.Service
	prefs   *prefs.Service
	privacy *privacy.Service
	handler *Handler
	db      *sql.DB
	web     *websess.Service
	// notify and presence are loaded with the plugins; the handler uses
	// them only after withNotify.
	notify   *notify.Service
	presence *presence.Tracker
	// idle, when set, replaces the idle timeout from the settings so tests
	// need not wait minutes.
	idle atomic.Int64
}

// startBBS runs a BBS with the given plugins (the hello test plugin if none).
func startBBS(t *testing.T, plugins ...plugin.Plugin) *env {
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
	if len(plugins) == 0 {
		plugins = []plugin.Plugin{&helloPlugin{}}
	}
	priv := privacy.NewService(db, as, ps, 14*24*time.Hour, nil, log)
	priv.SetPublisher(bus)
	for _, p := range plugins {
		if fc, ok := p.(privacy.FriendChecker); ok {
			priv.SetFriends(fc)
		}
	}
	nt := notify.NewService(db, as, nil, log)
	nt.Subscribe(bus)
	pres := presence.New(nil)
	reg, err := plugin.Load(ctx, plugin.Deps{DB: db, Perms: ps, Auth: as, Events: bus, Privacy: priv, Notify: nt, Presence: pres, Log: log}, plugins...)
	if err != nil {
		t.Fatal(err)
	}
	conns := presence.NewConns(nil)
	h := &Handler{Auth: as, Settings: st, Perms: ps, Prefs: pr, Menu: menu.NewService(db, ps, nil, log), Plugins: reg, Privacy: priv,
		Sessions: sessions.NewService(db, conns, nil, log), Log: log}
	h.Sessions.Subscribe(bus)
	web := websess.NewService(db, as, nil, log)
	web.Subscribe(bus)
	h.Sessions.SetWeb(web)
	if err := h.Menu.Seed(ctx, h.MenuDefaults()); err != nil {
		t.Fatal(err)
	}

	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(hostPriv)
	e := &env{auth: as, perms: ps, prefs: pr, privacy: priv, handler: h, db: db, web: web, notify: nt, presence: pres}
	srv, err := sshd.New(sshd.Config{
		HostKey: host, Auth: auth.NewSSHAuthenticator(as), Log: log,
		Handler: h, Conns: conns,
		Limits: func(ctx context.Context) sshd.Limits {
			l := st.ConnLimits(ctx)
			idle := time.Duration(l.IdleMinutes) * time.Minute
			if d := e.idle.Load(); d != 0 {
				idle = time.Duration(d)
			}
			return sshd.Limits{IdleTimeout: idle, MaxPerUser: l.MaxPerUser}
		},
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
	e.addr, e.hostKey = l.Addr().String(), host.PublicKey()
	return e
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

	// Log in with the key: line mode main menu, then log out (q).
	out = e.session(t, "alice", ssh.PublicKeys(signer), "q\r")
	for _, want := range []string{"Screen: shellshawk - Main menu", "Welcome, alice.", "2. Privacy and profile", "6. Administration"} {
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
	// the line-mode main menu, q logs out.
	input := "1" + "\x1b[B\x1b[B\x1b[B " + "\x13" + "\r" + "q\r"
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
	// Main menu 5 = Markdown, 1 = guide, Enter to finish reading,
	// 2 = Try it: type markdown, end with ".", then "no" to stop, q = back, q = log out.
	input := strings.Join([]string{"5", "1", "", "2", "# Hi", "[x](javascript:alert(1))", ".", "", "1", "q", "q"}, "\r") + "\r"
	out := e.session(t, "dave", ssh.PublicKeys(signer), input)
	for _, want := range []string{
		"Heading level 2: Emphasis",
		"Quote level 2:",
		"Code block start, language go, 2 lines:",
		"Link, grade ? Unclassified: https://example.org",
		"Section break.",
		"Screen: shellshawk - Preview",
		"Heading level 2: Hi", // under the screen title
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
	// Main menu: 7 = Broken item, 8 = Say hello; q logs out.
	out := e.session(t, "erin", ssh.PublicKeys(signer), "7\r\r8\r\rq\r")
	for _, want := range []string{"7. Broken item", "8. Say hello", "or q to log out",
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
	// 6 Administration; 9 Plugin settings; 1 Hello; greeting "Howdy";
	// Enter to dismiss "Settings saved."; q back to main; 8 Say hello; Enter;
	// 6 Administration; 10 Menu editor; 8 Administration entry (the editor
	// also lists the hidden notifications and web login items); 4 Delete; 2 Yes ->
	// protected message, Enter; q, q, then q logs out.
	input := strings.Join([]string{"6", "9", "1", "Howdy", "", "q", "8", "", "6", "10", "8", "4", "2", "", "q", "q", "q"}, "\r") + "\r"
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
	if !strings.Contains(out, "5. Markdown guide") || strings.Contains(out, ". Log out") || !strings.Contains(out, "or q to log out") {
		t.Errorf("menu numbering unexpected:\n%s", out)
	}
}

func TestMessagesEndToEnd(t *testing.T) {
	c := contacts.New()
	e := startBBS(t, c, messages.New(c))
	ctx := context.Background()
	ivyKey := e.accessibleAdmin(t, "ivy")
	ivy, _ := e.auth.UserByUsername(ctx, "ivy")
	code, _, _ := e.auth.CreateInvite(ctx, ivy.ID, auth.InviteOptions{})
	jackKey, line := newUserKey(t)
	jack, err := e.auth.Register(ctx, code, auth.Registration{Username: "jack", Password: testPassword, PublicKey: line})
	if err != nil {
		t.Fatal(err)
	}
	p := prefs.Default()
	p.Profile, p.PageSize = theme.ProfileAccessible, 200
	e.prefs.Set(ctx, jack.ID, p)

	// jack accepts messages from anyone (the default is friends only).
	jp, _ := e.privacy.Get(ctx, jack.ID)
	jp.Visibility[privacy.Messages] = privacy.Public
	if err := e.privacy.Update(ctx, jack.ID, jp); err != nil {
		t.Fatal(err)
	}
	// ivy (admin menu: 7 Contacts, 8 Messages): Messages, Write
	// (w), To jack, Subject, body in the line editor, finish with ".",
	// dismiss "Message sent.", back (q), Log out.
	out := e.session(t, "ivy", ssh.PublicKeys(ivyKey),
		strings.Join([]string{"8", "w", "jack", "Hello Jack", "**Welcome** aboard", ".", "", "q", "q"}, "\r")+"\r")
	if !strings.Contains(out, "Message sent.") {
		t.Fatalf("send failed:\n%s", out)
	}

	// jack (member menu: 6 Contacts, 7 Messages): Messages,
	// Inbox, first message, dismiss it, then q out of the message, the
	// inbox and Messages, and q again to log out.
	out = e.session(t, "jack", ssh.PublicKeys(jackKey),
		strings.Join([]string{"7", "1", "1", "", "q", "q", "q", "q"}, "\r")+"\r")
	for _, want := range []string{"Inbox: 1 unread, 0 read.", "1. New: Hello Jack", "From: ivy", "Welcome aboard", "1. Reply"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}

func TestPollEndToEnd(t *testing.T) {
	e := startBBS(t, polls.New())
	key := e.accessibleAdmin(t, "kim")
	// Main menu: 7 Polls. Polls (no polls yet): n Create.
	// Form: question; options typed one per line then "."; multi no;
	// named no; days 7; pinned no. Dismiss "Poll created.". Polls menu now:
	// 1 the poll. Poll menu: 1 Vote; choose option 2; results page, dismiss;
	// q back from the poll and from Polls; q logs out.
	input := strings.Join([]string{
		"7", "n", "Lunch?", "Pizza", "Soup", ".", "no", "no", "7", "no", "",
		"1", "1", "2", "", "q", "q", "q",
	}, "\r") + "\r"
	out := e.session(t, "kim", ssh.PublicKeys(key), input)
	for _, want := range []string{"Poll created.", "Votes are anonymous.", "Option 2, Soup: 1 vote(s), 100 percent (your vote).", "1 vote(s) from 1 member(s)."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}

// live is an interactive session for tests that must interleave input
// with output from other sessions.
type live struct {
	t     *testing.T
	in    io.WriteCloser
	out   *lockedBuf
	sess  *ssh.Session
	close func()
}

func (e *env) interactive(t *testing.T, user string, am ssh.AuthMethod) *live {
	t.Helper()
	c, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{am}, HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := c.NewSession()
	out := &lockedBuf{}
	sess.Stdout = out
	in, _ := sess.StdinPipe()
	if err := sess.RequestPty("xterm", 30, 100, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	l := &live{t: t, in: in, out: out, sess: sess, close: func() { sess.Close(); c.Close() }}
	t.Cleanup(l.close)
	return l
}

func (l *live) send(s string) {
	l.t.Helper()
	if _, err := l.in.Write([]byte(s)); err != nil {
		l.t.Fatal(err)
	}
}

func (l *live) waitFor(s string) {
	l.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(l.out.String(), s) {
		if time.Now().After(deadline) {
			l.t.Fatalf("timed out waiting for %q; output:\n%s", s, l.out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestChatBetweenTwoSessions(t *testing.T) {
	e := startBBS(t, chat.New())
	ctx := context.Background()
	leeKey := e.accessibleAdmin(t, "lee")
	lee, _ := e.auth.UserByUsername(ctx, "lee")
	code, _, _ := e.auth.CreateInvite(ctx, lee.ID, auth.InviteOptions{})
	miaKey, line := newUserKey(t)
	mia, err := e.auth.Register(ctx, code, auth.Registration{Username: "mia", Password: testPassword, PublicKey: line})
	if err != nil {
		t.Fatal(err)
	}
	p := prefs.Default()
	p.Profile = theme.ProfileAccessible
	e.prefs.Set(ctx, mia.ID, p)

	// lee: main menu 7 = Chat, then 1 = #lobby.
	a := e.interactive(t, "lee", ssh.PublicKeys(leeKey))
	a.waitFor("7. Chat")
	a.send("7\r")
	a.waitFor("#lobby [C]")
	a.send("1\r")
	a.waitFor("This chat is logged")

	// mia: main menu 6 = Chat (no Administration), then the lobby.
	b := e.interactive(t, "mia", ssh.PublicKeys(miaKey))
	b.waitFor("6. Chat")
	b.send("6\r")
	b.waitFor("#lobby [C] (1 here)")
	b.send("1\r")
	a.waitFor("* mia joined")

	b.send("hello lee\r")
	a.waitFor("mia: hello lee") // delivered live to the other session

	a.send("/who\r")
	a.waitFor("In #lobby: lee, mia.")
	// mia cannot kick (not a moderator); lee, an administrator, can.
	b.send("/kick lee\r")
	b.waitFor("You do not have permission to do that.")
	a.send("/kick mia\r")
	a.waitFor("* mia was removed by lee")
	b.waitFor("You were removed from this chat.")
	b.waitFor("#lobby [C] (1 here)") // back at the channel list
	a.waitFor("* mia left")
}

func TestConferenceEndToEnd(t *testing.T) {
	pl, ch := polls.New(), chat.New()
	e := startBBS(t, pl, ch, conferences.New(pl, ch))
	key := e.accessibleAdmin(t, "nora")
	// Main menu: 7 Chat, 8 Conferences, 9 Polls; q logs out.
	// Conferences: area 1 (General), conference 1 (General discussion),
	// n Start a thread: title, body in the line editor, "." to post,
	// 1 = no poll, read the thread (Enter), 2 Reply: body, ".", no poll,
	// read again (Enter), then q back out of thread, conference, area and
	// areas, and q again to log out.
	input := strings.Join([]string{
		"8", "1", "1", "n", "Hello all", "Welcome **everyone**", "# Plans", ".", "1", "",
		"2", "A reply", ".", "1", "",
		"q", "q", "q", "q", "q",
	}, "\r") + "\r"
	out := e.session(t, "nora", ssh.PublicKeys(key), input)
	for _, want := range []string{
		"Heading level 2: Post 1 of 1, by nora",
		"Welcome everyone",
		"Heading level 3: Plans", // the member's "#", under the post heading
		"Heading level 2: Post 2 of 2, by nora",
		"Actions: n Start a thread; d Delete this conference; q Back.",
		"1. Hello all", // threads are numbered from 1, after the actions
		"A reply",
		"Your post is published. Add a poll to it?",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}

func TestEraseAccountEndToEnd(t *testing.T) {
	e := startBBS(t)
	ctx := context.Background()
	_ = e.accessibleAdmin(t, "pat")
	admin, _ := e.auth.UserByUsername(ctx, "pat")
	code, _, _ := e.auth.CreateInvite(ctx, admin.ID, auth.InviteOptions{})
	key, line := newUserKey(t)
	olga, err := e.auth.Register(ctx, code, auth.Registration{Username: "olga", Password: testPassword, PublicKey: line})
	if err != nil {
		t.Fatal(err)
	}
	p := prefs.Default()
	p.Profile = theme.ProfileAccessible
	e.prefs.Set(ctx, olga.ID, p)
	webTok, _, err := e.web.Create(ctx, olga.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Main menu 2 = Privacy and profile; 4 = Erase my account; dismiss the
	// explanation; content 1 = delete; type a wrong name, then the right
	// one; confirm 2 = Yes; dismiss the final notice (session ends).
	input := strings.Join([]string{"2", "4", "", "1", "olgaa", "olga", "2", ""}, "\r") + "\r"
	out := e.session(t, "olga", ssh.PublicKeys(key), input)
	// The request ends the session that asked, like every other one, with
	// the date.
	for _, want := range []string{"erased after 14 days", "does not match your username", "Your account is locked and will be erased on",
		"To cancel, contact an administrator before then. This connection has ended."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
	if _, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
		User: "olga", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)}, HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 5 * time.Second,
	}); err == nil {
		t.Error("locked account can still log in")
	}
	if er, ok, _ := e.privacy.Erasure(ctx, olga.ID); !ok || !er.DeleteContent {
		t.Errorf("erasure request = %+v, %v", er, ok)
	}
	// Asked from her own session, which the request ends: her web session
	// must still be deleted, and stay gone after a cancellation.
	if err := e.privacy.CancelErasure(ctx, admin.ID, olga.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.web.Lookup(ctx, webTok); err == nil {
		t.Error("web session survived an erasure requested from SSH")
	}
}

func TestWebLoginCodeItem(t *testing.T) {
	e := startBBS(t)
	key := e.accessibleAdmin(t, "quinn")
	if out := e.session(t, "quinn", ssh.PublicKeys(key), "q\r"); strings.Contains(out, "Web login code") {
		t.Error("web login item shown with the web interface disabled")
	}
	e.handler.WebLogin = websess.NewService(e.db, e.auth, nil, slog.New(slog.DiscardHandler))
	// Main menu: 6 = Web login code (before Administration); dismiss; q.
	out := e.session(t, "quinn", ssh.PublicKeys(key), "6\r\rq\r")
	code := regexp.MustCompile(`\b[0-9A-Z]{4}-[0-9A-Z]{4}\b`).FindString(out)
	if code == "" {
		t.Fatalf("no code shown:\n%s", out)
	}
	if uid, err := e.handler.WebLogin.Redeem(context.Background(), "quinn", code); err != nil || uid == 0 {
		t.Errorf("shown code does not work: %v", err)
	}
}

// panicLoginPlugin's login hook panics, to prove a plugin bug cannot stop
// members logging in or later hooks running.
type panicLoginPlugin struct{}

func (panicLoginPlugin) Manifest() plugin.Manifest {
	return plugin.Manifest{ID: "brokenlogin", Name: "Broken login", Version: "0.0.1",
		OnLogin: func(context.Context, plugin.Session) error { panic("login hook bug") }}
}
func (panicLoginPlugin) Init(context.Context, *plugin.Host) error { return nil }

func TestMOTDAfterLogin(t *testing.T) {
	m := motd.New()
	e := startBBS(t, panicLoginPlugin{}, m, wall.New())
	signer := e.accessibleAdmin(t, "erin")
	erin, _ := e.auth.UserByUsername(context.Background(), "erin")
	if err := m.Set(context.Background(), erin.ID, "**Welcome** to the test BBS"); err != nil {
		t.Fatal(err)
	}
	// First login: the message, dismissed with Enter, then the main menu
	// (7 Message of the day, 8 Wall): q logs out.
	out := e.session(t, "erin", ssh.PublicKeys(signer), "\rq\r")
	for _, want := range []string{"Screen: shellshawk - Message of the day", "Welcome to the test BBS", "7. Message of the day", "8. Wall"} {
		if !strings.Contains(out, want) {
			t.Errorf("first login missing %q", want)
		}
	}
	if strings.Contains(out, "login hook bug") {
		t.Error("panic detail leaked to the member")
	}
	if strings.Index(out, "Welcome to the test BBS") > strings.Index(out, "Main menu") {
		t.Error("message of the day shown after the main menu, not before")
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
	// Second login: already seen, straight to the menu.
	if out := e.session(t, "erin", ssh.PublicKeys(signer), "q\r"); strings.Contains(out, "Welcome to the test BBS") {
		t.Errorf("message shown again:\n%s", out)
	}
}
