package sshd

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// ---- test doubles -------------------------------------------------------

// testAuth accepts registered keys (as ModeMember) and passwords mapped to
// a fixed Identity, which may be deliberately invalid.
type testAuth struct {
	keys      map[string]string // SHA256 fingerprint → user ID
	passwords map[string]Identity
}

func (a testAuth) PublicKey(_ ConnInfo, key ssh.PublicKey) (Identity, error) {
	if uid, ok := a.keys[ssh.FingerprintSHA256(key)]; ok {
		return Identity{UserID: uid, Mode: ModeMember}, nil
	}
	return Identity{}, ErrDenied
}

func (a testAuth) Password(_ ConnInfo, pw []byte) (Identity, error) {
	if id, ok := a.passwords[string(pw)]; ok {
		return id, nil
	}
	return Identity{}, ErrDenied
}

// interactiveHandler greets the user, reports resizes, and returns when the
// client closes stdin or the context ends.
type interactiveHandler struct{}

func (interactiveHandler) HandleShell(ctx context.Context, s *Session) {
	term := ""
	if s.PTY != nil {
		term = fmt.Sprintf("%s %dx%d", s.PTY.Term, s.PTY.Columns, s.PTY.Rows)
	}
	fmt.Fprintf(s, "hello mode=%s user=%s term=%q lang=%q\n", s.Identity.Mode, s.Identity.UserID, term, s.Env["LANG"])

	eof := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, s); close(eof) }()
	for {
		select {
		case <-ctx.Done():
			return
		case <-eof:
			return
		case ws := <-s.Resize:
			fmt.Fprintf(s, "resize %dx%d\n", ws.Columns, ws.Rows)
		}
	}
}

// ---- harness ------------------------------------------------------------

func quietLog() *slog.Logger { return slog.New(slog.DiscardHandler) }

func newSigner(t *testing.T, kind string) ssh.Signer {
	t.Helper()
	var key any
	var err error
	switch kind {
	case "ed25519":
		_, key, err = ed25519.GenerateKey(rand.Reader)
	case "ecdsa256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "ecdsa384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "rsa2048":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa3072":
		key, err = rsa.GenerateKey(rand.Reader, 3072)
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type harness struct {
	addr    string
	srv     *Server
	hostPub ssh.PublicKey
	userKey ssh.Signer // registered as user "u1"
}

func start(t *testing.T, mod func(*Config, *testAuth)) *harness {
	t.Helper()
	host := newSigner(t, "ed25519")
	user := newSigner(t, "ed25519")
	auth := &testAuth{
		keys:      map[string]string{ssh.FingerprintSHA256(user.PublicKey()): "u1"},
		passwords: map[string]Identity{"invite-code": {Mode: ModeRegister, InviteCode: "invite-code"}},
	}
	cfg := Config{HostKey: host, Handler: interactiveHandler{}, Log: quietLog()}
	if mod != nil {
		mod(&cfg, auth)
	}
	if cfg.Auth == nil {
		cfg.Auth = auth
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(l) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("Shutdown: %v", err)
		}
		if err := <-served; !errors.Is(err, ErrServerClosed) {
			t.Errorf("Serve returned %v, want ErrServerClosed", err)
		}
	})
	return &harness{addr: l.Addr().String(), srv: srv, hostPub: host.PublicKey(), userKey: user}
}

func (h *harness) clientConfig(auth ...ssh.AuthMethod) *ssh.ClientConfig {
	if len(auth) == 0 {
		auth = []ssh.AuthMethod{ssh.PublicKeys(h.userKey)}
	}
	return &ssh.ClientConfig{
		User:            "someone",
		Auth:            auth,
		HostKeyCallback: ssh.FixedHostKey(h.hostPub),
		Timeout:         5 * time.Second,
	}
}

func (h *harness) dial(t *testing.T, cfg *ssh.ClientConfig) *ssh.Client {
	t.Helper()
	c, err := ssh.Dial("tcp", h.addr, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// lineReader reads lines from a session's stdout with a timeout so a broken
// server fails the test instead of hanging it.
type lineReader struct {
	lines chan string
}

func newLineReader(r io.Reader) *lineReader {
	lr := &lineReader{lines: make(chan string, 16)}
	go func() {
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			lr.lines <- sc.Text()
		}
		close(lr.lines)
	}()
	return lr
}

func (lr *lineReader) next(t *testing.T) string {
	t.Helper()
	select {
	case l, ok := <-lr.lines:
		if !ok {
			t.Fatal("stdout closed, expected a line")
		}
		return l
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for output")
	}
	return ""
}

// ---- crypto policy ------------------------------------------------------

func TestKeyExchangePolicy(t *testing.T) {
	h := start(t, nil)
	tests := []struct {
		kex    string
		wantOK bool
	}{
		{ssh.KeyExchangeMLKEM768X25519, true},
		{ssh.KeyExchangeCurve25519, true},
		{ssh.KeyExchangeECDHP256, false},
		{ssh.KeyExchangeECDHP521, false},
		{ssh.KeyExchangeDH14SHA256, false},
		{ssh.KeyExchangeDH16SHA512, false},
	}
	for _, tt := range tests {
		t.Run(tt.kex, func(t *testing.T) {
			cfg := h.clientConfig()
			cfg.KeyExchanges = []string{tt.kex}
			c, err := ssh.Dial("tcp", h.addr, cfg)
			if c != nil {
				c.Close()
			}
			if (err == nil) != tt.wantOK {
				t.Errorf("Dial with kex %s: err = %v, wantOK %v", tt.kex, err, tt.wantOK)
			}
		})
	}
}

func TestPostQuantumPreferred(t *testing.T) {
	if KeyExchanges[0] != ssh.KeyExchangeMLKEM768X25519 {
		t.Fatalf("first KEX = %s, want %s", KeyExchanges[0], ssh.KeyExchangeMLKEM768X25519)
	}
}

func TestCipherPolicy(t *testing.T) {
	h := start(t, nil)
	tests := []struct {
		cipher string
		wantOK bool
	}{
		{ssh.CipherChaCha20Poly1305, true},
		{ssh.CipherAES256GCM, true},
		{ssh.CipherAES128GCM, true},
		{ssh.CipherAES128CTR, false},
		{ssh.CipherAES256CTR, false},
	}
	for _, tt := range tests {
		t.Run(tt.cipher, func(t *testing.T) {
			cfg := h.clientConfig()
			cfg.Ciphers = []string{tt.cipher}
			c, err := ssh.Dial("tcp", h.addr, cfg)
			if c != nil {
				c.Close()
			}
			if (err == nil) != tt.wantOK {
				t.Errorf("Dial with cipher %s: err = %v, wantOK %v", tt.cipher, err, tt.wantOK)
			}
		})
	}
}

func TestUserKeyPolicy(t *testing.T) {
	sha1RSA := func(t *testing.T) ssh.Signer {
		s := newSigner(t, "rsa3072")
		as, err := ssh.NewSignerWithAlgorithms(s.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
		if err != nil {
			t.Fatal(err)
		}
		return as
	}
	tests := []struct {
		name   string
		signer func(*testing.T) ssh.Signer
		wantOK bool
	}{
		{"ed25519", func(t *testing.T) ssh.Signer { return newSigner(t, "ed25519") }, true},
		{"ecdsa p256", func(t *testing.T) ssh.Signer { return newSigner(t, "ecdsa256") }, true},
		{"ecdsa p384", func(t *testing.T) ssh.Signer { return newSigner(t, "ecdsa384") }, false},
		{"rsa 2048", func(t *testing.T) ssh.Signer { return newSigner(t, "rsa2048") }, false},
		{"rsa 3072 sha2", func(t *testing.T) ssh.Signer { return newSigner(t, "rsa3072") }, true},
		{"rsa 3072 sha1 signature", sha1RSA, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := tt.signer(t)
			h := start(t, func(_ *Config, a *testAuth) {
				a.keys[ssh.FingerprintSHA256(signer.PublicKey())] = "u2"
			})
			c, err := ssh.Dial("tcp", h.addr, h.clientConfig(ssh.PublicKeys(signer)))
			if c != nil {
				c.Close()
			}
			if (err == nil) != tt.wantOK {
				t.Errorf("err = %v, wantOK %v", err, tt.wantOK)
			}
		})
	}
}

func TestCheckUserKey(t *testing.T) {
	tests := []struct {
		kind   string
		wantOK bool
	}{
		{"ed25519", true}, {"ecdsa256", true}, {"ecdsa384", false}, {"rsa2048", false}, {"rsa3072", true},
	}
	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			err := CheckUserKey(newSigner(t, tt.kind).PublicKey())
			if (err == nil) != tt.wantOK {
				t.Errorf("CheckUserKey(%s) = %v, wantOK %v", tt.kind, err, tt.wantOK)
			}
		})
	}
}

// ---- authentication -----------------------------------------------------

func TestAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		denyAll  bool
		auth     func(h *harness) []ssh.AuthMethod
		wantOK   bool
		wantLine string // greeting prefix when wantOK
	}{
		{
			name:     "registered key",
			auth:     func(h *harness) []ssh.AuthMethod { return []ssh.AuthMethod{ssh.PublicKeys(h.userKey)} },
			wantOK:   true,
			wantLine: "hello mode=member user=u1",
		},
		{
			name: "unknown key",
			auth: func(*harness) []ssh.AuthMethod {
				return []ssh.AuthMethod{ssh.PublicKeys(newSigner(t, "ed25519"))}
			},
		},
		{
			name:     "invite password gets register mode only",
			auth:     func(*harness) []ssh.AuthMethod { return []ssh.AuthMethod{ssh.Password("invite-code")} },
			wantOK:   true,
			wantLine: "hello mode=register user=",
		},
		{
			name: "password can never grant member mode",
			auth: func(*harness) []ssh.AuthMethod { return []ssh.AuthMethod{ssh.Password("bad-impl")} },
		},
		{
			name: "add-key mode requires a user id",
			auth: func(*harness) []ssh.AuthMethod { return []ssh.AuthMethod{ssh.Password("no-user")} },
		},
		{
			name: "register mode requires the invite code",
			auth: func(*harness) []ssh.AuthMethod { return []ssh.AuthMethod{ssh.Password("no-code")} },
		},
		{
			name: "wrong password",
			auth: func(*harness) []ssh.AuthMethod { return []ssh.AuthMethod{ssh.Password("nope")} },
		},
		{
			name:    "deny all",
			denyAll: true,
			auth:    func(h *harness) []ssh.AuthMethod { return []ssh.AuthMethod{ssh.PublicKeys(h.userKey)} },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := start(t, func(c *Config, a *testAuth) {
				a.passwords["bad-impl"] = Identity{UserID: "u1", Mode: ModeMember}
				a.passwords["no-user"] = Identity{Mode: ModeAddKey}
				a.passwords["no-code"] = Identity{Mode: ModeRegister}
				if tt.denyAll {
					c.Auth = DenyAll{}
				}
			})
			c, err := ssh.Dial("tcp", h.addr, h.clientConfig(tt.auth(h)...))
			if !tt.wantOK {
				if err == nil {
					c.Close()
					t.Fatal("Dial succeeded, want auth failure")
				}
				return
			}
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer c.Close()
			sess, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			out, _ := sess.StdoutPipe()
			lr := newLineReader(out)
			if err := sess.Shell(); err != nil {
				t.Fatal(err)
			}
			if got := lr.next(t); !strings.HasPrefix(got, tt.wantLine) {
				t.Errorf("greeting = %q, want prefix %q", got, tt.wantLine)
			}
		})
	}
}

// ---- channels and requests ---------------------------------------------

func TestNonSessionChannelsRefused(t *testing.T) {
	h := start(t, nil)
	c := h.dial(t, h.clientConfig())

	for _, typ := range []string{"direct-tcpip", "x11", "forwarded-tcpip", "direct-streamlocal@openssh.com", "bogus"} {
		t.Run(typ, func(t *testing.T) {
			_, _, err := c.OpenChannel(typ, nil)
			var oce *ssh.OpenChannelError
			if !errors.As(err, &oce) || oce.Reason != ssh.Prohibited {
				t.Errorf("OpenChannel(%s) err = %v, want Prohibited", typ, err)
			}
		})
	}
	// Port forwarding through the client API is refused too.
	if conn, err := c.Dial("tcp", "127.0.0.1:1"); err == nil {
		conn.Close()
		t.Error("direct-tcpip forward succeeded")
	}
}

func TestGlobalRequestsRefused(t *testing.T) {
	h := start(t, nil)
	c := h.dial(t, h.clientConfig())
	payload := ssh.Marshal(struct {
		Addr string
		Port uint32
	}{"127.0.0.1", 0})
	ok, _, err := c.SendRequest("tcpip-forward", true, payload)
	if err != nil || ok {
		t.Errorf("tcpip-forward: ok=%v err=%v, want refused", ok, err)
	}
}

func TestSessionRequestPolicy(t *testing.T) {
	h := start(t, nil)
	c := h.dial(t, h.clientConfig())

	env := func(k, v string) []byte { return ssh.Marshal(envRequestMsg{k, v}) }
	pty := func(term string, cols, rows uint32) []byte {
		return ssh.Marshal(ptyRequestMsg{Term: term, Columns: cols, Rows: rows})
	}
	tests := []struct {
		name    string
		req     string
		payload []byte
		wantOK  bool
	}{
		{"exec refused", "exec", ssh.Marshal(struct{ Cmd string }{"id"}), false},
		{"sftp refused when no handler configured", "subsystem", ssh.Marshal(subsystemRequestMsg{"sftp"}), false},
		{"other subsystem refused", "subsystem", ssh.Marshal(subsystemRequestMsg{"netconf"}), false},
		{"x11 refused", "x11-req", nil, false},
		{"agent forwarding refused", "auth-agent-req@openssh.com", nil, false},
		{"signal refused", "signal", ssh.Marshal(struct{ Sig string }{"KILL"}), false},
		{"env LANG allowed", "env", env("LANG", "en_US.UTF-8"), true},
		{"env LD_PRELOAD refused", "env", env("LD_PRELOAD", "/x.so"), false},
		{"env PATH refused", "env", env("PATH", "/bin"), false},
		{"env oversized refused", "env", env("LANG", strings.Repeat("x", maxEnvLen)), false},
		{"pty ok", "pty-req", pty("xterm-256color", 80, 24), true},
		{"pty bad term", "pty-req", pty("xterm\x1b[31m", 80, 24), false},
		{"pty zero size uses defaults (RFC 4254 §6.2)", "pty-req", pty("xterm", 0, 0), true},
		{"pty huge size", "pty-req", pty("xterm", 5000, 24), false},
		{"pty malformed", "pty-req", []byte{1, 2, 3}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			ok, err := sess.SendRequest(tt.req, true, tt.payload)
			if err != nil {
				t.Fatalf("SendRequest: %v", err)
			}
			if ok != tt.wantOK {
				t.Errorf("%s ok = %v, want %v", tt.req, ok, tt.wantOK)
			}
		})
	}
}

func TestShellSession(t *testing.T) {
	h := start(t, nil)
	c := h.dial(t, h.clientConfig())
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	stdin, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	lr := newLineReader(out)
	if err := sess.Setenv("LANG", "en_GB.UTF-8"); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	if err := sess.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("Shell: %v", err)
	}

	want := `hello mode=member user=u1 term="xterm-256color 80x24" lang="en_GB.UTF-8"`
	if got := lr.next(t); got != want {
		t.Errorf("greeting = %q, want %q", got, want)
	}

	if err := sess.WindowChange(40, 100); err != nil {
		t.Fatalf("WindowChange: %v", err)
	}
	if got := lr.next(t); got != "resize 100x40" {
		t.Errorf("resize line = %q", got)
	}

	// After the shell starts, a second shell, a pty-req and exec are refused.
	for _, r := range []struct {
		typ     string
		payload []byte
	}{
		{"shell", nil},
		{"pty-req", ssh.Marshal(ptyRequestMsg{Term: "xterm", Columns: 80, Rows: 24})},
		{"exec", ssh.Marshal(struct{ Cmd string }{"sh"})},
	} {
		if ok, err := sess.SendRequest(r.typ, true, r.payload); err != nil || ok {
			t.Errorf("%s after shell: ok=%v err=%v, want refused", r.typ, ok, err)
		}
	}

	stdin.Close() // handler sees EOF and returns
	if err := sess.Wait(); err != nil {
		t.Errorf("Wait: %v (want clean exit-status 0)", err)
	}
}

func TestSessionsPerConnectionLimit(t *testing.T) {
	h := start(t, nil)
	c := h.dial(t, h.clientConfig())
	for i := range maxSessionsPerConn {
		s, err := c.NewSession()
		if err != nil {
			t.Fatalf("session %d: %v", i+1, err)
		}
		defer s.Close()
	}
	if s, err := c.NewSession(); err == nil {
		s.Close()
		t.Fatal("session beyond limit was accepted")
	}
}

// ---- connection limits and lifecycle -------------------------------------

func TestMaxConnections(t *testing.T) {
	h := start(t, func(c *Config, _ *testAuth) { c.MaxConns = 1 })
	first := h.dial(t, h.clientConfig())
	_ = first

	c, err := ssh.Dial("tcp", h.addr, h.clientConfig())
	if err == nil {
		c.Close()
		t.Fatal("second connection accepted beyond MaxConns=1")
	}
}

func TestHandshakeTimeout(t *testing.T) {
	h := start(t, func(c *Config, _ *testAuth) { c.HandshakeTimeout = 200 * time.Millisecond })
	conn, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Send nothing; the server must hang up on its own.
	_, err = io.Copy(io.Discard, conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("server did not close an idle unauthenticated connection")
	}
}

func TestShutdownEndsActiveSessions(t *testing.T) {
	host := newSigner(t, "ed25519")
	user := newSigner(t, "ed25519")
	srv, err := New(Config{
		HostKey: host, Handler: interactiveHandler{}, Log: quietLog(),
		Auth: testAuth{keys: map[string]string{ssh.FingerprintSHA256(user.PublicKey()): "u1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(l)

	c, err := ssh.Dial("tcp", l.Addr().String(), &ssh.ClientConfig{
		User: "u", Auth: []ssh.AuthMethod{ssh.PublicKeys(user)},
		HostKeyCallback: ssh.FixedHostKey(host.PublicKey()), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	sess, _ := c.NewSession()
	lr := newLineReader(must(sess.StdoutPipe()))
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	lr.next(t) // handler is now blocked waiting for input

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v (sessions should end when their context is cancelled)", err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestNewValidation(t *testing.T) {
	host := newSigner(t, "ed25519")
	full := Config{HostKey: host, Auth: DenyAll{}, Handler: interactiveHandler{}, Log: quietLog()}
	tests := []struct {
		name string
		mod  func(*Config)
	}{
		{"no host key", func(c *Config) { c.HostKey = nil }},
		{"no auth", func(c *Config) { c.Auth = nil }},
		{"no handler", func(c *Config) { c.Handler = nil }},
		{"no logger", func(c *Config) { c.Log = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := full
			tt.mod(&c)
			if _, err := New(c); err == nil {
				t.Error("New() error = nil, want error")
			}
		})
	}
	if _, err := New(full); err != nil {
		t.Errorf("New(valid) = %v", err)
	}
}

// recordingAuth wraps testAuth, marks one key as pending, and records logins.
type recordingAuth struct {
	testAuth
	pendingFP string
	logins    chan Identity
}

func (a *recordingAuth) PublicKey(c ConnInfo, key ssh.PublicKey) (Identity, error) {
	if ssh.FingerprintSHA256(key) == a.pendingFP {
		return Identity{UserID: "p1", Mode: ModePending}, nil
	}
	return a.testAuth.PublicKey(c, key)
}

func (a *recordingAuth) RecordLogin(_ context.Context, id Identity) { a.logins <- id }

func TestPendingModeAndLoginRecording(t *testing.T) {
	pendingKey := newSigner(t, "ed25519")
	var rec *recordingAuth
	h := start(t, func(c *Config, a *testAuth) {
		rec = &recordingAuth{testAuth: *a, pendingFP: ssh.FingerprintSHA256(pendingKey.PublicKey()), logins: make(chan Identity, 4)}
		c.Auth = rec
	})

	tests := []struct {
		name     string
		signer   ssh.Signer
		wantMode Mode
		wantUser string
	}{
		{"member key", h.userKey, ModeMember, "u1"},
		{"pending key", pendingKey, ModePending, "p1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := h.dial(t, h.clientConfig(ssh.PublicKeys(tt.signer)))
			sess, err := c.NewSession()
			if err != nil {
				t.Fatal(err)
			}
			defer sess.Close()
			lr := newLineReader(must(sess.StdoutPipe()))
			if err := sess.Shell(); err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("hello mode=%s user=%s", tt.wantMode, tt.wantUser)
			if got := lr.next(t); !strings.HasPrefix(got, want) {
				t.Errorf("greeting = %q, want prefix %q", got, want)
			}
			select {
			case id := <-rec.logins:
				if id.Mode != tt.wantMode || id.UserID != tt.wantUser || id.KeyFingerprint != ssh.FingerprintSHA256(tt.signer.PublicKey()) {
					t.Errorf("RecordLogin got %+v", id)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("RecordLogin not called")
			}
		})
	}

	// A client offering an unknown key first and the real key second must
	// produce exactly one recorded login, for the key that was proven.
	stranger := newSigner(t, "ed25519")
	c := h.dial(t, h.clientConfig(ssh.PublicKeys(stranger, h.userKey)))
	defer c.Close()
	select {
	case id := <-rec.logins:
		if id.KeyFingerprint != ssh.FingerprintSHA256(h.userKey.PublicKey()) {
			t.Errorf("recorded fingerprint %s, want the proven key", id.KeyFingerprint)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RecordLogin not called")
	}
	select {
	case id := <-rec.logins:
		t.Errorf("unexpected extra RecordLogin: %+v", id)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestZeroSizePTYUsesDefaults(t *testing.T) {
	h := start(t, nil)
	c := h.dial(t, h.clientConfig())
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	lr := newLineReader(must(sess.StdoutPipe()))
	if err := sess.RequestPty("xterm", 0, 0, ssh.TerminalModes{}); err != nil {
		t.Fatalf("RequestPty 0x0: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	if got := lr.next(t); !strings.Contains(got, `term="xterm 80x24"`) {
		t.Errorf("greeting = %q, want default 80x24", got)
	}
}
