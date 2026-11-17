package chat

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/plugin"
)

func TestSay(t *testing.T) {
	f := setup(t)
	lobby, _ := f.p.ByName(f.Ctx, "lobby")
	tests := []struct {
		name, text string
		want       error
	}{
		{"ok", "hello there", nil},
		{"trimmed", "  hi  ", nil},
		{"empty", "   ", ErrInvalid},
		{"too long", strings.Repeat("x", MaxMessage+1), ErrInvalid},
		{"escape sequence", "hi\x1b[2J", ErrInvalid},
		{"newline", "two\nlines", ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := f.p.Say(f.Ctx, lobby, f.user(t, f.alice), tt.text); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	hist, _ := f.p.History(f.Ctx, lobby, 10, time.Time{}, time.Time{})
	if len(hist) != 2 || hist[1].Body != "hi" {
		t.Errorf("logged = %+v, want the two valid messages, trimmed", hist)
	}

	bob := f.user(t, f.bob)
	for i := range floodLines {
		if err := f.p.Say(f.Ctx, lobby, bob, "m"+strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.p.Say(f.Ctx, lobby, bob, "one too many"); !errors.Is(err, ErrSlowDown) {
		t.Errorf("flood err = %v, want ErrSlowDown", err)
	}
	if got := sentence(fmt.Errorf("%w: the message is empty", ErrInvalid)); got != "The message is empty." {
		t.Errorf("sentence = %q", got)
	}
}

func TestWebSend(t *testing.T) {
	f := setup(t)
	lobby, _ := f.p.ByName(f.Ctx, "lobby")
	priv, err := f.p.createAdHoc(f.Ctx, f.alice, "plans", "", "bob")
	if err != nil {
		t.Fatal(err)
	}
	id := func(n int64) map[string]string { return map[string]string{"id": strconv.FormatInt(n, 10)} }
	form := func(msg string) url.Values { return url.Values{"message": {msg}, "return": {"/p/conferences/t/1"}} }

	tests := []struct {
		name       string
		user       int64
		channel    int64
		msg        string
		wantStatus int  // WebError status, 0 for none
		notFound   bool // ErrWebNotFound
	}{
		{"ok", f.alice, lobby.ID, "hello from the web", 0, false},
		{"command", f.alice, lobby.ID, "/who", 400, false},
		{"empty", f.alice, lobby.ID, " ", 400, false},
		{"control characters", f.alice, lobby.ID, "a\x07b", 400, false},
		{"private chat, invited", f.bob, priv, "hi", 0, false},
		{"private chat, not invited", f.carol, priv, "hi", 0, true},
		{"no such channel", f.alice, 99999, "hi", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := f.WebPost(f.p, "/c/{id}/send", id(tt.channel), form(tt.msg), tt.user)
			var werr *plugin.WebError
			switch {
			case tt.notFound:
				if !errors.Is(err, plugin.ErrWebNotFound) {
					t.Errorf("err = %v, want not found", err)
				}
			case tt.wantStatus != 0:
				if !errors.As(err, &werr) || werr.Status != tt.wantStatus {
					t.Errorf("err = %v, want WebError %d", err, tt.wantStatus)
				}
			case err != nil:
				t.Errorf("err = %v", err)
			case page.Redirect != "/p/conferences/t/1#chat":
				t.Errorf("redirect = %q", page.Redirect)
			}
		})
	}
	hist, _ := f.p.History(f.Ctx, lobby, 10, time.Time{}, time.Time{})
	if len(hist) != 1 || hist[0].Body != "hello from the web" || hist[0].UserID != f.alice {
		t.Errorf("lobby log = %+v", hist)
	}
}

// stream runs the events route for user in a goroutine and waits until the
// member has joined the channel.
func (f *fixture) stream(t *testing.T, ctx context.Context, user, channel int64) <-chan string {
	t.Helper()
	f.p.hub.mu.Lock()
	before := len(f.p.hub.rooms[channel])
	f.p.hub.mu.Unlock()
	out := make(chan string, 1)
	go func() {
		rec, err := f.WebStream(ctx, f.p, "/c/{id}/events", map[string]string{"id": strconv.FormatInt(channel, 10)}, user)
		if err != nil {
			out <- "error: " + err.Error()
			return
		}
		out <- rec.Header().Get("Content-Type") + "\n" + rec.Body.String()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f.p.hub.mu.Lock()
		n := len(f.p.hub.rooms[channel])
		f.p.hub.mu.Unlock()
		if n > before {
			return out
		}
		if time.Now().After(deadline) {
			t.Fatal("stream never joined the channel")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestWebEvents(t *testing.T) {
	f := setup(t)
	lobby, _ := f.p.ByName(f.Ctx, "lobby")
	ctx, cancel := context.WithCancel(f.Ctx)
	out := f.stream(t, ctx, f.alice, lobby.ID)
	if who := f.p.hub.who(lobby.ID); len(who) != 1 || who[0] != "alice" {
		t.Errorf("who = %v, want alice (web members are in the channel)", who)
	}
	if err := f.p.Say(f.Ctx, lobby, f.user(t, f.bob), "hello web"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond) // let the line reach the stream
	cancel()
	got := <-out
	for _, want := range []string{"text/event-stream", "retry: 5000", "event: line\ndata: [", "bob: hello web\n\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("stream missing %q:\n%s", want, got)
		}
	}
	if n := f.p.hub.count(lobby.ID); n != 0 {
		t.Errorf("%d still in the channel after the stream ended", n)
	}
}

func TestWebEventsEndWhenClosed(t *testing.T) {
	f := setup(t)
	priv, err := f.p.createAdHoc(f.Ctx, f.alice, "plans", "", "bob")
	if err != nil {
		t.Fatal(err)
	}
	out := f.stream(t, f.Ctx, f.bob, priv) // no cancel: closing must end it
	if err := f.p.Destroy(f.Ctx, f.alice, priv); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-out:
		if !strings.Contains(got, "data: This chat was closed.") || !strings.Contains(got, "event: end\n") {
			t.Errorf("stream after close:\n%s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end when the chat was closed")
	}
}

func TestWebEventsAndPanelAccess(t *testing.T) {
	f := setup(t)
	priv, err := f.p.createAdHoc(f.Ctx, f.alice, "plans", "", "bob")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WebStream(f.Ctx, f.p, "/c/{id}/events", map[string]string{"id": strconv.FormatInt(priv, 10)}, f.carol); !errors.Is(err, plugin.ErrWebNotFound) {
		t.Errorf("uninvited stream err = %v, want not found", err)
	}
	if html, err := f.p.WebPanel(f.Ctx, f.carol, priv, "Chat", "tok", "/back"); err != nil || html != "" {
		t.Errorf("uninvited panel = %q, %v; want nothing", html, err)
	}

	c, _ := f.p.Get(f.Ctx, priv)
	if err := f.p.Say(f.Ctx, c, f.user(t, f.alice), "<b>not bold</b>"); err != nil {
		t.Fatal(err)
	}
	html, err := f.p.WebPanel(f.Ctx, f.bob, priv, "Thread chat", "tok-123", "/p/conferences/t/9")
	if err != nil {
		t.Fatal(err)
	}
	base := "/p/chat/c/" + strconv.FormatInt(priv, 10)
	for _, want := range []string{
		`data-live-events="` + base + `/events"`, `action="` + base + `/send"`,
		`name="csrf" value="tok-123"`, `name="return" value="/p/conferences/t/9"`,
		"alice: &lt;b&gt;not bold&lt;/b&gt;", `role="log"`, `<label for="chat-message">`,
	} {
		if !strings.Contains(string(html), want) {
			t.Errorf("panel missing %q:\n%s", want, html)
		}
	}
}
