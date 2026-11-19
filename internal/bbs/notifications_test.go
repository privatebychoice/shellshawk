package bbs

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/notify"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// pingPlugin sends "ping:ping" notifications; opening one says so.
type pingPlugin struct{}

func (pingPlugin) Manifest() plugin.Manifest {
	return plugin.Manifest{ID: "ping", Name: "Ping", Version: "0.0.1",
		Notifications: []plugin.NotificationKind{{Key: "ping", Label: "Pings", Default: true, OpenLabel: "See the ping",
			Open: func(ctx context.Context, s plugin.Session, n notify.Notification) error {
				return tui.Message(ctx, s.UI(), s.Title("Ping"), "Ping opened: "+n.Text)
			}}}}
}

func (pingPlugin) Init(context.Context, *plugin.Host) error { return nil }

// withNotify shows notifications in the BBS before any session starts.
func withNotify(e *env) { e.handler.Notify = e.notify }

func TestNotificationsBetweenScreens(t *testing.T) {
	e := startBBS(t, &helloPlugin{}, pingPlugin{})
	withNotify(e)
	ctx := context.Background()
	signer := e.accessibleAdmin(t, "nina")
	nina, _ := e.auth.UserByUsername(ctx, "nina")
	ping := func(text string) {
		t.Helper()
		if _, ok, err := e.notify.Add(ctx, notify.New{UserID: nina.ID, Kind: "ping:ping", ActorID: nina.ID, Text: text}); err != nil || !ok {
			t.Fatal(ok, err)
		}
	}
	run := func(input ...string) string {
		t.Helper()
		return e.session(t, "nina", ssh.PublicKeys(signer), strings.Join(input, "\r")+"\r")
	}
	ordered := func(t *testing.T, out string, want ...string) {
		t.Helper()
		at := 0
		for _, w := range want {
			i := strings.Index(out[at:], w)
			if i < 0 {
				t.Errorf("missing %q after position %d\n%s", w, at, out)
				return
			}
			at += i + len(w)
		}
	}

	// Main menu (line mode): 1 Notifications ... 9 Say hello.
	ping("one")
	ping("two")
	t.Run("listed when opening an item, then seen", func(t *testing.T) {
		out := run("9", "q", "", "q")
		ordered(t, out, "Welcome, nina. You have 2 new notifications.", "1. Notifications (2 new)",
			"Screen: shellshawk - New notifications", "You have 2 new notification(s).", "1. Pings, from nina: one", "2. Pings, from nina: two",
			"or q to continue", "Hello from a plugin.", "Screen: shellshawk - Main menu", "1. Notifications. Pages")
		if n, _ := e.notify.CountUnseen(ctx, nina.ID); n != 0 {
			t.Errorf("%d still new", n)
		}
	})

	ping("three")
	t.Run("opened from the list between screens", func(t *testing.T) {
		out := run("9", "1", "", "", "q")
		ordered(t, out, "1. Pings, from nina: three", "Ping opened: three", "Hello from a plugin.")
	})

	t.Run("the Notifications screen", func(t *testing.T) {
		// 1 Notifications (no list between screens for it); 1 the newest;
		// 2 Delete; d Delete all, 1 No; q back; q log out.
		out := run("1", "1", "2", "d", "1", "q", "q")
		ordered(t, out, "Screen: shellshawk - Notifications", "Actions: s Notification settings; d Delete all; q Back.",
			"1. Pings, from nina: three", "2. Pings, from nina: two", "3. Pings, from nina: one", "Pings, from nina: three. just now.", "1. See the ping", "2. Delete this notification",
			"1. Pings, from nina: two", "Delete all 2 notification(s)?")
		if strings.Contains(out, "New notifications") {
			t.Error("new-notification list shown when opening Notifications")
		}
		if list, _ := e.notify.List(ctx, nina.ID); len(list) != 2 {
			t.Errorf("%d left, want 2", len(list))
		}
	})

	t.Run("settings: off between screens", func(t *testing.T) {
		// 1 Notifications; s settings: between screens no, Pings yes;
		// Enter; q; q.
		out := run("1", "s", "no", "yes", "", "q", "q")
		ordered(t, out, "Show new notifications between screens? Type yes or no (currently yes)",
			"Receive notifications for: Pings? Type yes or no (currently yes)", "Your notification settings have been saved.")
		ping("four")
		out = run("9", "", "q")
		ordered(t, out, "You have 1 new notification.", "1. Notifications (1 new)", "Hello from a plugin.")
		if strings.Contains(out, "New notifications") {
			t.Error("listed between screens after turning it off")
		}
	})

	t.Run("settings: a kind turned off is not received", func(t *testing.T) {
		run("1", "s", "yes", "no", "", "q", "q")
		if _, ok, _ := e.notify.Add(ctx, notify.New{UserID: nina.ID, Kind: "ping:ping"}); ok {
			t.Error("a turned-off kind was added")
		}
	})
}

func TestNotificationsFullScreen(t *testing.T) {
	e := startBBS(t)
	withNotify(e)
	ctx := context.Background()
	code, _ := e.auth.CreateBootstrapInvite(ctx)
	signer, keyLine := newUserKey(t)
	u, err := e.auth.Register(ctx, code, auth.Registration{Username: "fay", Password: testPassword, PublicKey: keyLine})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.notify.Register(notify.Kind{Name: "test:note", Label: "Notes", Default: true}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.notify.Add(ctx, notify.New{UserID: u.ID, Kind: "test:note", Text: "full screen note"}); err != nil {
		t.Fatal(err)
	}
	// 5 opens Terminal test; q continues past the list; Enter closes the
	// test; q logs out.
	out := e.session(t, "fay", ssh.PublicKeys(signer), "5"+"q"+"\r"+"q")
	iList, iNote, iTest := strings.Index(out, "New notifications"), strings.Index(out, "Notes: full screen note"), strings.Index(out, "Each line below uses one text style")
	if iList < 0 || iNote < iList || iTest < iNote || !strings.Contains(out, "(1 new)") {
		t.Errorf("list %d, note %d, test %d\n%q", iList, iNote, iTest, out)
	}
}
