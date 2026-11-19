package bbs

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/prefs"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/transition"
)

// withTransitions gives the BBS a transition service before any session
// starts.
func withTransitions(e *env) *transition.Service {
	e.handler.Transitions = transition.NewService(e.db, nil, slog.New(slog.DiscardHandler))
	return e.handler.Transitions
}

func TestTransitionScreens(t *testing.T) {
	e := startBBS(t)
	tr := withTransitions(e)
	ctx := context.Background()
	code, _ := e.auth.CreateBootstrapInvite(ctx)
	signer, keyLine := newUserKey(t)
	u, err := e.auth.Register(ctx, code, auth.Registration{Username: "tess", Password: testPassword, PublicKey: keyLine})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct{ slug, art string }{{"hello", "HELLO-ART ╔═╗"}, {"bye", "BYE-ART"}} {
		if err := tr.Upload(ctx, u.ID, f.slug, "art.txt", []byte(f.art)); err != nil {
			t.Fatal(err)
		}
	}
	hello, _ := tr.ProfileBySlug(ctx, "hello")
	bye, _ := tr.ProfileBySlug(ctx, "bye")
	set := func(target, moment string, c transition.Choice) {
		t.Helper()
		if err := tr.SetPoint(ctx, u.ID, target, moment, c, e.handler.itemExists); err != nil {
			t.Fatal(err)
		}
	}
	set(transition.DefaultTarget, transition.Enter, transition.Choice{ProfileID: hello.ID})
	set(transition.DefaultTarget, transition.Exit, transition.Choice{ProfileID: bye.ID})

	// Full screen: 4 opens Terminal test. The opening screen waits for a
	// key (x), Enter closes the test, x dismisses the leaving screen, and
	// q logs out.
	run := func(input string) string {
		t.Helper()
		return e.session(t, "tess", ssh.PublicKeys(signer), input)
	}
	out := run("4" + "x" + "\r" + "x" + "q")
	iHello, iTest, iBye := strings.Index(out, "HELLO-ART ╔═╗"), strings.Index(out, "Each line below uses one text style"), strings.Index(out, "BYE-ART")
	if iHello < 0 || iTest < iHello || iBye < iTest || !strings.Contains(out, "Press any key to continue") {
		t.Errorf("order: hello %d, test %d, bye %d\n%q", iHello, iTest, iBye, out)
	}

	// An item's own setting overrides the default: nothing when leaving.
	set("core:termtest", transition.Exit, transition.Choice{})
	if out = run("4" + "x" + "\r" + "q"); !strings.Contains(out, "HELLO-ART") || strings.Contains(out, "BYE-ART") {
		t.Errorf("item override not applied\n%q", out)
	}

	// ASCII-only terminals get an approximation.
	p := prefs.Default()
	p.ASCIIOnly = true
	e.prefs.Set(ctx, u.ID, p)
	if out = run("4" + "x" + "\r" + "q"); !strings.Contains(out, "HELLO-ART +-+") {
		t.Errorf("ASCII approximation missing\n%q", out)
	}

	// Turned off in display settings, and never in line mode.
	tests := []struct {
		name  string
		p     prefs.Prefs
		input string
	}{
		{"turned off", prefs.Prefs{Profile: theme.ProfileModern, Theme: theme.DefaultTheme, PageSize: 20}, "4" + "\r" + "q"},
		{"line mode", prefs.Prefs{Profile: theme.ProfileAccessible, Theme: theme.DefaultTheme, PageSize: 200, Transitions: true}, "4\r\rq\r"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := e.prefs.Set(ctx, u.ID, tt.p); err != nil {
				t.Fatal(err)
			}
			if out := run(tt.input); strings.Contains(out, "HELLO-ART") || !strings.Contains(out, "Terminal test") {
				t.Errorf("transition shown\n%q", out)
			}
		})
	}
}

func TestTransitionEditor(t *testing.T) {
	e := startBBS(t)
	tr := withTransitions(e)
	ctx := context.Background()
	signer := e.accessibleAdmin(t, "ivan")

	// 6 Administration, 11 Transitions, 1 Profiles, a Add: name "Bad Name"
	// is refused, then "welcome". In the profile: w Write a new file
	// "logo.txt", two lines then "."; Enter dismisses "File saved."; p
	// Preview, Enter; q, q back to Transitions; 2 Where they are shown,
	// 1 Default: opening = 2 (welcome), leaving = 1 (nothing); Enter
	// dismisses "Saved."; then q until logged out.
	input := strings.Join([]string{
		"6", "11", "1", "a", "Bad Name", "welcome",
		"w", "logo.txt", "  /\\_/\\", " ( o.o )", ".", "",
		"p", "",
		"q", "q", "2", "1", "2", "1", "",
		"q", "q", "q", "q",
	}, "\r") + "\r"
	out := e.session(t, "ivan", ssh.PublicKeys(signer), input)
	for _, want := range []string{"11. Transitions", "Use 1 to 40 lowercase letters", "SFTP folder: /text/welcome/", "File saved.", " ( o.o )",
		"Opening: welcome. Leaving: nothing.", "Saved."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	p, err := tr.ProfileBySlug(ctx, "welcome")
	if err != nil || p.Files != 1 {
		t.Fatalf("profile = %+v, %v", p, err)
	}
	if body, _, _ := tr.ReadFile(ctx, p.ID, "logo.txt"); body != "  /\\_/\\\n ( o.o )" {
		t.Errorf("file = %q", body)
	}
	if text, ok, _ := tr.Pick(ctx, "core:keys", transition.Enter); !ok || !strings.Contains(text, "o.o") {
		t.Errorf("default opening = %q, %v", text, ok)
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}

func TestTransitionEditorNeedsPermission(t *testing.T) {
	e := startBBS(t)
	withTransitions(e)
	ctx := context.Background()
	_ = e.accessibleAdmin(t, "judy")
	signer := e.member(t, "judy", "kim")
	judy, _ := e.auth.UserByUsername(ctx, "judy")
	kim, _ := e.auth.UserByUsername(ctx, "kim")
	mods, _ := e.perms.GroupByName(ctx, perm.GroupModerator)
	if err := e.perms.AddMember(ctx, judy.ID, mods.ID, kim.ID); err != nil {
		t.Fatal(err)
	}
	// Moderators see Administration (6) but not Transitions.
	out := e.session(t, "kim", ssh.PublicKeys(signer), "6qq")
	if !strings.Contains(out, "Accounts awaiting approval") || strings.Contains(out, "Transitions") {
		t.Errorf("moderator's administration menu:\n%s", out)
	}
}
