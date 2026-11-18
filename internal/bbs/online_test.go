package bbs

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/prefs"
	"go.privatebychoice.com/shellshawk/internal/sessions"
	"go.privatebychoice.com/shellshawk/internal/settings"
	"go.privatebychoice.com/shellshawk/internal/theme"
)

// member registers an ordinary member using line mode.
func (e *env) member(t *testing.T, inviter, name string) ssh.Signer {
	t.Helper()
	ctx := context.Background()
	by, _ := e.auth.UserByUsername(ctx, inviter)
	code, _, err := e.auth.CreateInvite(ctx, by.ID, auth.InviteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	signer, line := newUserKey(t)
	u, err := e.auth.Register(ctx, code, auth.Registration{Username: name, Password: testPassword, PublicKey: line})
	if err != nil {
		t.Fatal(err)
	}
	p := prefs.Default()
	p.Profile = theme.ProfileAccessible
	if err := e.prefs.Set(ctx, u.ID, p); err != nil {
		t.Fatal(err)
	}
	return signer
}

func TestWhoIsOnlineEndsConnection(t *testing.T) {
	e := startBBS(t)
	adaKey := e.accessibleAdmin(t, "ada")
	melKey := e.member(t, "ada", "mel")

	mel := e.interactive(t, "mel", ssh.PublicKeys(melKey))
	mel.waitFor("or q to log out")

	ada := e.interactive(t, "ada", ssh.PublicKeys(adaKey))
	ada.waitFor("or q to log out")
	ada.send("6\r") // Administration
	ada.waitFor("3. Who is online. See SSH connections and end one")
	ada.send("3\r")
	ada.waitFor("2 connection(s) open. Choose one to end it.")
	ada.waitFor("1. mel: 1 terminal, idle under a minute")
	ada.waitFor("2. ada: 1 terminal, idle under a minute (this connection)")
	ada.waitFor("Actions: r Refresh; q Back.")

	ada.send("2\r") // own connection: explained, not ended
	ada.waitFor("This is your own connection.")
	ada.send("\r")
	ada.send("1\r")
	ada.waitFor("End this connection? mel: 1 terminal")
	ada.send("2\r") // Yes
	ada.waitFor("The connection has been ended.")
	mel.waitFor(sessions.EndedMessage)
	done := make(chan error, 1)
	go func() { done <- mel.sess.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ended connection still open")
	}

	ada.send("\r")
	ada.waitFor("1 connection(s) open.")
	var n int
	e.db.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'connection.ended'`).Scan(&n)
	if n != 1 {
		t.Errorf("audit entries = %d, want 1", n)
	}
}

func TestIdleDisconnect(t *testing.T) {
	e := startBBS(t)
	_ = e.accessibleAdmin(t, "ada")
	melKey := e.member(t, "ada", "mel")
	e.idle.Store(int64(time.Second))

	mel := e.interactive(t, "mel", ssh.PublicKeys(melKey))
	mel.waitFor("or q to log out")
	mel.waitFor("No activity: disconnecting in")
	mel.waitFor("seconds. Press an arrow key to stay connected.")
	mel.waitFor("You have been disconnected after 1 second without activity.")
}

func TestConnectionLimitsForm(t *testing.T) {
	e := startBBS(t)
	adaKey := e.accessibleAdmin(t, "ada")
	// 6 Administration; 8 Connection limits; an idle timeout of 1 is refused,
	// then 45; 2 connections; Enter to dismiss; q, q, then q logs out.
	input := strings.Join([]string{"6", "8", "1", "45", "2", "", "q", "q"}, "\r") + "\r"
	out := e.session(t, "ada", ssh.PublicKeys(adaKey), input)
	for _, want := range []string{
		"8. Connection limits. Idle timeout and connections per account",
		"Current value: 30.", "Current value: 3.",
		"idle timeout must be 0 (off) or 2 to 1440 minutes",
		"Connection limits saved.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
	if got := e.handler.Settings.ConnLimits(context.Background()); got != (settings.ConnLimits{IdleMinutes: 45, MaxPerUser: 2}) {
		t.Errorf("limits = %+v", got)
	}
}

func TestLockEndsConnections(t *testing.T) {
	e := startBBS(t)
	_ = e.accessibleAdmin(t, "ada")
	melKey := e.member(t, "ada", "mel")
	ctx := context.Background()
	ada, _ := e.auth.UserByUsername(ctx, "ada")
	mel, _ := e.auth.UserByUsername(ctx, "mel")

	first := e.interactive(t, "mel", ssh.PublicKeys(melKey))
	first.waitFor("or q to log out")
	second := e.interactive(t, "mel", ssh.PublicKeys(melKey))
	second.waitFor("or q to log out")

	if err := e.auth.SetLocked(ctx, ada.ID, mel.ID, true); err != nil {
		t.Fatal(err)
	}
	for _, l := range []*live{first, second} {
		l.waitFor(sessions.LockedMessage)
		done := make(chan error, 1)
		go func() { done <- l.sess.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("locked account's connection still open")
		}
	}
}

func TestRejectEndsConnections(t *testing.T) {
	e := startBBS(t)
	_ = e.accessibleAdmin(t, "ada")
	ctx := context.Background()
	ada, _ := e.auth.UserByUsername(ctx, "ada")
	code, _, err := e.auth.CreateInvite(ctx, ada.ID, auth.InviteOptions{RequireApproval: true})
	if err != nil {
		t.Fatal(err)
	}
	key, line := newUserKey(t)
	pat, err := e.auth.Register(ctx, code, auth.Registration{Username: "pat", Password: testPassword, PublicKey: line})
	if err != nil || pat.Status != auth.StatusPending {
		t.Fatalf("register = %+v, %v", pat, err)
	}

	waiting := e.interactive(t, "pat", ssh.PublicKeys(key))
	waiting.waitFor("waiting for approval")
	if err := e.auth.Reject(ctx, ada.ID, pat.ID); err != nil {
		t.Fatal(err)
	}
	waiting.waitFor(sessions.RejectedMessage)
	done := make(chan error, 1)
	go func() { done <- waiting.sess.Wait() }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("rejected account's connection still open")
	}
}
