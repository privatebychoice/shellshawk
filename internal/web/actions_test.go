package web

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func (e *env) csrf(t *testing.T, cookie *http.Cookie) string {
	t.Helper()
	sess, err := e.sessions.Lookup(context.Background(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	return sess.CSRF
}

func TestPluginActions(t *testing.T) {
	e := setup(t, false)
	cookie := e.login(t, e.alice, "alice")
	tok := e.csrf(t, cookie)
	const origin = "https://bbs.example.net"

	tests := []struct {
		name         string
		form         url.Values
		origin       string
		cookie       *http.Cookie
		accept       string
		wantStatus   int
		wantLocation string
		wantBody     string
	}{
		{"saved, back to the page", url.Values{"csrf": {tok}, "note": {"hi"}, "to": {"/p/notes/?x=1#chat"}}, origin, cookie, "", 303, "/p/notes/?x=1#chat", ""},
		{"no csrf token", url.Values{"note": {"hi"}}, origin, cookie, "", 403, "", "session has ended"},
		{"wrong csrf token", url.Values{"csrf": {"nope"}, "note": {"hi"}}, origin, cookie, "", 403, "", ""},
		{"not logged in", url.Values{"csrf": {tok}, "note": {"hi"}}, origin, nil, "", 403, "", ""},
		{"other site", url.Values{"csrf": {tok}, "note": {"hi"}}, "https://evil.example", cookie, "", 403, "", ""},
		{"plugin rejects, page", url.Values{"csrf": {tok}, "note": {"bad"}}, origin, cookie, "", 400, "", "Notes cannot be bad."},
		{"plugin rejects, script", url.Values{"csrf": {tok}, "note": {"bad"}}, origin, cookie, "text/plain", 400, "", "Notes cannot be bad."},
		{"form shown again with its errors", url.Values{"csrf": {tok}, "note": {"retry"}}, origin, cookie, "", 422, "", `<h1>Write a note</h1>`},
		{"offsite redirect refused", url.Values{"csrf": {tok}, "to": {"//evil.example/x"}}, origin, cookie, "", 303, "/home", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.do(req{method: "POST", path: "/p/notes/save", form: tt.form, origin: tt.origin, cookie: tt.cookie,
				headers: map[string]string{"Accept": tt.accept}})
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d: %s", rec.Code, tt.wantStatus, rec.Body)
			}
			if tt.wantLocation != "" && rec.Header().Get("Location") != tt.wantLocation {
				t.Errorf("Location = %q, want %q", rec.Header().Get("Location"), tt.wantLocation)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body missing %q: %s", tt.wantBody, rec.Body)
			}
			if tt.accept == "text/plain" && rec.Body.String() != tt.wantBody {
				t.Errorf("plain-text error = %q, want just the message", rec.Body)
			}
		})
	}
}

func TestLocalPath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/p/conferences/t/1#chat", "/p/conferences/t/1#chat"},
		{"/home", "/home"},
		{"", "/home"},
		{"//evil.example/x", "/home"},
		{"https://evil.example/", "/home"},
		{"javascript:alert(1)", "/home"},
		{"/\\evil.example", "/home"},
		{"/a\r\nSet-Cookie: x=1", "/home"},
		{"p/relative", "/home"},
	}
	for _, tt := range tests {
		if got := localPath(tt.in); got != tt.want {
			t.Errorf("localPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// openStream starts a stream over a real connection (streams need one) and
// returns the response once its headers arrive.
func openStream(t *testing.T, ts *httptest.Server, cookie *http.Cookie) *http.Response {
	t.Helper()
	q, _ := http.NewRequest("GET", ts.URL+"/p/notes/live", nil)
	if cookie != nil {
		q.AddCookie(cookie)
	}
	res, err := ts.Client().Do(q)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

// ended reports whether the stream body reaches EOF within a few seconds.
func ended(res *http.Response) bool {
	done := make(chan struct{})
	go func() {
		_, _ = bufio.NewReader(res.Body).ReadString(0) // until EOF
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}

func TestPluginStreams(t *testing.T) {
	old := sessionRecheck
	sessionRecheck = 50 * time.Millisecond
	t.Cleanup(func() { sessionRecheck = old })

	e := setup(t, true) // plain-HTTP test server: insecure cookies
	ts := httptest.NewServer(e.h)
	t.Cleanup(ts.Close)

	if res := openStream(t, ts, nil); res.StatusCode != http.StatusUnauthorized {
		t.Errorf("logged-out stream status = %d, want 401", res.StatusCode)
	}

	cookie := e.login(t, e.alice, "alice")
	var open []*http.Response
	for range maxStreamsPerUser {
		res := openStream(t, ts, cookie)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("stream status = %d", res.StatusCode)
		}
		open = append(open, res)
	}
	line, _ := bufio.NewReader(open[0].Body).ReadString('\n')
	if want := "data: hello "; !strings.HasPrefix(line, want) {
		t.Errorf("first line = %q, want %q…", line, want)
	}
	if res := openStream(t, ts, cookie); res.StatusCode != http.StatusTooManyRequests {
		t.Errorf("stream over the limit status = %d, want 429", res.StatusCode)
	}

	// Logging out ends the member's streams.
	if err := e.sessions.Delete(context.Background(), cookie.Value); err != nil {
		t.Fatal(err)
	}
	for i, res := range open {
		if !ended(res) {
			t.Fatalf("stream %d still open after logout", i)
		}
	}

	// Shutting down ends every stream.
	cookie = e.login(t, e.alice, "alice")
	res := openStream(t, ts, cookie)
	e.srv.CloseStreams()
	if !ended(res) {
		t.Error("stream still open after CloseStreams")
	}
}

// TestStreamOutlivesServerTimeouts runs a stream on a server whose read and
// write timeouts are far shorter than the stream stays open: the stream
// must lift them rather than be cut off.
func TestStreamOutlivesServerTimeouts(t *testing.T) {
	e := setup(t, true)
	ts := httptest.NewUnstartedServer(e.h)
	ts.Config.ReadTimeout = 100 * time.Millisecond
	ts.Config.WriteTimeout = 100 * time.Millisecond
	ts.Start()
	t.Cleanup(ts.Close)

	res := openStream(t, ts, e.login(t, e.alice, "alice"))
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	eof := make(chan struct{})
	go func() {
		_, _ = bufio.NewReader(res.Body).ReadString(0)
		close(eof)
	}()
	select {
	case <-eof:
		t.Fatal("stream was cut off by the server's timeouts")
	case <-time.After(time.Second):
	}
	e.srv.CloseStreams()
	select {
	case <-eof:
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end on CloseStreams")
	}
}

func TestHomePanels(t *testing.T) {
	e := setup(t, false)
	cookie := e.login(t, e.alice, "alice")
	rec := e.do(req{method: "GET", path: "/home", cookie: cookie})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `<section class="notes-panel">Notes for you</section>`) {
		t.Errorf("home = %d, missing the plugin panel:\n%s", rec.Code, rec.Body)
	}
}
