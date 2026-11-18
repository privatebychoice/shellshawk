package sshd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/presence"
)

// limitHandler reports idle warnings and, when its connection is ended on
// purpose, the reason, then returns. It echoes nothing.
type limitHandler struct{}

func (limitHandler) HandleShell(ctx context.Context, s *Session) {
	fmt.Fprintf(s, "hello conn=%d\n", s.ConnSerial)
	go func() { _, _ = io.Copy(io.Discard, s) }()
	for {
		select {
		case <-ctx.Done():
			var d *presence.Disconnect
			if errors.As(context.Cause(ctx), &d) {
				fmt.Fprintf(s, "bye: %s\n", d.Message)
			}
			return
		case <-s.IdleWarning:
			fmt.Fprintln(s, "warned")
		}
	}
}

// startLimited runs a server whose test key belongs to user 7, so the
// per-account limit applies to it.
func startLimited(t *testing.T, limits *atomic.Pointer[Limits], conns *presence.Conns) *harness {
	t.Helper()
	return start(t, func(c *Config, a *testAuth) {
		for fp := range a.keys {
			a.keys[fp] = "7"
		}
		c.Handler = limitHandler{}
		c.Conns = conns
		c.Limits = func(context.Context) Limits { return *limits.Load() }
		c.idleCheck = 50 * time.Millisecond
	})
}

// openShell starts a PTY-less shell and returns its stdin and stdout.
func openShell(t *testing.T, c *ssh.Client) (*ssh.Session, io.WriteCloser, *lineReader) {
	t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	in, _ := sess.StdinPipe()
	out, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	return sess, in, newLineReader(out)
}

func TestPerAccountLimit(t *testing.T) {
	var limits atomic.Pointer[Limits]
	limits.Store(&Limits{MaxPerUser: 1})
	conns := presence.NewConns(nil)
	h := startLimited(t, &limits, conns)

	first := h.dial(t, h.clientConfig())
	_, _, lr := openShell(t, first)
	if got := lr.next(t); !strings.HasPrefix(got, "hello conn=") {
		t.Fatalf("first connection: %q", got)
	}

	// A second connection authenticates, then is told why it is refused.
	second := h.dial(t, h.clientConfig())
	sess, err := second.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	sess.Stderr = &stderr
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Errorf("pty-req refused: %v", err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatalf("shell refused: %v (the member would see a failed request, not the reason)", err)
	}
	err = sess.Wait()
	var exit *ssh.ExitError
	if !errors.As(err, &exit) || exit.ExitStatus() != 1 {
		t.Errorf("Wait = %v, want exit status 1", err)
	}
	if !strings.Contains(stderr.String(), "This account already has 1 connection(s) open, the most allowed at once.") {
		t.Errorf("stderr = %q", stderr.String())
	}
	// An SFTP client is told the same.
	sftpConn := h.dial(t, h.clientConfig())
	sftpSess, err := sftpConn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	sftpErr, _ := sftpSess.StderrPipe()
	if err := sftpSess.RequestSubsystem("sftp"); err != nil {
		t.Fatalf("sftp refused without the reason: %v", err)
	}
	// The x/crypto client cannot Wait on a subsystem; read until it closes.
	if b, _ := io.ReadAll(sftpErr); !strings.Contains(string(b), "the most allowed at once") {
		t.Errorf("sftp stderr = %q", b)
	}
	if n := len(conns.List()); n != 1 {
		t.Errorf("registry holds %d connections, want 1", n)
	}

	// Raising the limit applies to the next connection.
	limits.Store(&Limits{MaxPerUser: 2})
	third := h.dial(t, h.clientConfig())
	_, _, lr3 := openShell(t, third)
	if got := lr3.next(t); !strings.HasPrefix(got, "hello conn=") {
		t.Errorf("after raising the limit: %q", got)
	}
}

func TestIdleWarningAndDisconnect(t *testing.T) {
	var limits atomic.Pointer[Limits]
	limits.Store(&Limits{IdleTimeout: 800 * time.Millisecond})
	h := startLimited(t, &limits, nil)

	c := h.dial(t, h.clientConfig())
	sess, in, lr := openShell(t, c)
	lr.next(t) // hello

	// Typing keeps the connection open well past the timeout.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				_, _ = in.Write([]byte("x"))
			}
		}
	})
	time.Sleep(1500 * time.Millisecond)
	close(stop)
	wg.Wait()

	// Then silence: a warning, then the disconnect with its reason.
	if got := lr.next(t); got != "warned" {
		t.Fatalf("expected the idle warning first, got %q", got)
	}
	if got := lr.next(t); got != "bye: You have been disconnected after 1 second without activity." {
		t.Errorf("disconnect line = %q", got)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("connection not closed after the idle timeout")
	}
}

func TestIdleTimeoutOff(t *testing.T) {
	var limits atomic.Pointer[Limits]
	limits.Store(&Limits{})
	h := startLimited(t, &limits, nil)
	c := h.dial(t, h.clientConfig())
	_, _, lr := openShell(t, c)
	lr.next(t)
	time.Sleep(300 * time.Millisecond)
	// Turning it on applies to the open connection.
	limits.Store(&Limits{IdleTimeout: 200 * time.Millisecond})
	if got := lr.next(t); got != "warned" {
		t.Errorf("after turning the timeout on: %q", got)
	}
}

func TestEndConnection(t *testing.T) {
	var limits atomic.Pointer[Limits]
	limits.Store(&Limits{})
	conns := presence.NewConns(nil)
	h := startLimited(t, &limits, conns)
	c := h.dial(t, h.clientConfig())
	sess, _, lr := openShell(t, c)
	lr.next(t)

	list := conns.List()
	if len(list) != 1 || list[0].UserID != 7 || list[0].Mode != string(ModeMember) || list[0].Terminals != 1 {
		t.Fatalf("registry = %+v", list)
	}
	if !conns.End(list[0].ID, &presence.Disconnect{Message: "Ended by staff."}) {
		t.Fatal("End reported the connection missing")
	}
	// The handler gets to say goodbye before the connection closes.
	if got := lr.next(t); got != "bye: Ended by staff." {
		t.Errorf("goodbye = %q", got)
	}
	_ = sess.Wait()
	deadline := time.Now().Add(5 * time.Second)
	for len(conns.List()) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("connection still registered after it ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDescribeDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{time.Minute, "1 minute"},
		{30 * time.Minute, "30 minutes"},
		{90 * time.Second, "90 seconds"},
		{time.Second, "1 second"},
		{800 * time.Millisecond, "1 second"},
		{2 * time.Second, "2 seconds"},
	}
	for _, tt := range tests {
		if got := describeDuration(tt.d); got != tt.want {
			t.Errorf("describeDuration(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestIdleWarningTime(t *testing.T) {
	tests := []struct{ timeout, want time.Duration }{
		{30 * time.Minute, time.Minute},
		{2 * time.Minute, 30 * time.Second},
		{800 * time.Millisecond, 200 * time.Millisecond},
	}
	for _, tt := range tests {
		if got := idleWarning(tt.timeout); got != tt.want {
			t.Errorf("idleWarning(%v) = %v, want %v", tt.timeout, got, tt.want)
		}
	}
}
