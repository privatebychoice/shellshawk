package motd

import (
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugins/plugintest"
)

type fixture struct {
	*plugintest.Env
	p          *Plugin
	alice, mod int64
}

func setup(t *testing.T) *fixture {
	t.Helper()
	p := New()
	p.now = func() time.Time { return time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC) }
	e := plugintest.New(t, p)
	return &fixture{Env: e, p: p, alice: e.User("alice"), mod: e.User("mod1", perm.GroupModerator)}
}

func TestSet(t *testing.T) {
	f := setup(t)
	tests := []struct {
		name  string
		actor int64
		body  string
		want  error
	}{
		{"member may not", f.alice, "hi", perm.ErrForbidden},
		{"moderator", f.mod, "**Welcome**", nil},
		{"administrator", f.Admin, "Maintenance *tonight*", nil},
		{"too long", f.mod, strings.Repeat("x", MaxBody+1), ErrInvalid},
		{"escape sequence", f.mod, "hi\x1b[2J", ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := f.p.Set(f.Ctx, tt.actor, tt.body); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	m, err := f.p.Get(f.Ctx)
	if err != nil || m.Body != "Maintenance *tonight*" || m.UpdatedBy != "admin1" || m.Version != 2 {
		t.Errorf("message = %+v, %v", m, err)
	}
}

func TestShownOnceAfterLogin(t *testing.T) {
	f := setup(t)
	login := func() string {
		s := f.Session(f.alice, "\r")
		if err := f.p.onLogin(f.Ctx, s); err != nil {
			t.Fatalf("onLogin: %v", err)
		}
		return s.Out.String()
	}
	if out := login(); out != "" {
		t.Errorf("shown with no message:\n%s", out)
	}
	f.p.Set(f.Ctx, f.mod, "**Welcome** to the BBS")
	tests := []struct {
		name  string
		setup func()
		shown bool
	}{
		{"new message", func() {}, true},
		{"already seen", func() {}, false},
		{"changed", func() { f.p.Set(f.Ctx, f.mod, "Changed") }, true},
		{"cleared", func() { f.p.Set(f.Ctx, f.mod, "") }, false},
		{"set again after clearing", func() { f.p.Set(f.Ctx, f.mod, "Back again") }, true},
	}
	for _, tt := range tests {
		tt.setup()
		out := login()
		if shown := strings.Contains(out, "Message of the day"); shown != tt.shown {
			t.Errorf("%s: shown = %v, want %v\n%s", tt.name, shown, tt.shown, out)
		}
	}
}

func TestMenuEdit(t *testing.T) {
	f := setup(t)
	// Moderator: Write (1), editor lines finished with ".", dismiss
	// "Saved.", Read (1), dismiss, Back (4).
	s := f.Session(f.mod, strings.Join([]string{"1", "Hello *all*", ".", "", "1", "", "4"}, "\r")+"\r")
	if err := f.p.run(f.Ctx, s); err != nil {
		t.Fatalf("run: %v\n%s", err, s.Out)
	}
	if m, _ := f.p.Get(f.Ctx); m.Body != "Hello *all*" {
		t.Errorf("saved body = %q\n%s", m.Body, s.Out)
	}
	// A member only reads it.
	s = f.Session(f.alice, "\r")
	if err := f.p.run(f.Ctx, s); err != nil {
		t.Fatal(err)
	}
	if out := s.Out.String(); !strings.Contains(out, "Hello all") || strings.Contains(out, "Edit the message") {
		t.Errorf("member view:\n%s", out)
	}
}

func TestWebHomeAndPrivacy(t *testing.T) {
	f := setup(t)
	ws := plugintest.WebSession{Env: f.Env, User: f.alice, Plugin: "motd"}
	if html, err := f.p.webHome(httptest.NewRequest("GET", "/home", nil), ws); err != nil || html != "" {
		t.Errorf("panel with no message = %q, %v", html, err)
	}
	f.p.Set(f.Ctx, f.mod, "**Hi** <script>x</script>")
	html, err := f.p.webHome(httptest.NewRequest("GET", "/home", nil), ws)
	if err != nil || !strings.Contains(string(html), "<strong>Hi</strong>") || strings.Contains(string(html), "<script>") ||
		!strings.Contains(string(html), "by mod1") {
		t.Errorf("panel = %s, %v", html, err)
	}

	s := f.Session(f.alice, "\r")
	f.p.onLogin(f.Ctx, s)
	files, err := f.p.export(f.Ctx, f.alice)
	if err != nil || !strings.Contains(string(files[0].Data), `"last_version_seen": 1`) {
		t.Errorf("export = %s, %v", files[0].Data, err)
	}
	if files, _ := f.p.export(f.Ctx, f.mod); !strings.Contains(string(files[0].Data), "current_message_set_by_you") {
		t.Errorf("author export = %s", files[0].Data)
	}
	for _, u := range []int64{f.alice, f.mod} {
		if err := f.p.erase(f.Ctx, events.Event{UserID: u}); err != nil {
			t.Fatal(err)
		}
	}
	if _, unseen, _ := f.p.Unseen(f.Ctx, f.alice); !unseen {
		t.Error("erased member's seen record kept")
	}
	if m, _ := f.p.Get(f.Ctx); m.UpdatedBy != "" || m.Body == "" {
		t.Errorf("after the author's erasure = %+v; want the message kept without their name", m)
	}
}
