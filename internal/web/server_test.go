package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/prefs"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/version"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// notesPlugin adds web pages for the tests.
type notesPlugin struct{}

var notesTmpl = template.Must(template.New("n").Parse(`<p>Hello {{.}}</p>`))

func (notesPlugin) Manifest() plugin.Manifest {
	page := func(title string) func(*http.Request, plugin.WebSession) (plugin.WebPage, error) {
		return func(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
			var b bytes.Buffer
			notesTmpl.Execute(&b, "<script>alert(1)</script>")
			body := template.HTML(b.String()) + s.Markdown("**md** [x](javascript:alert(1))")
			return plugin.WebPage{Title: title, Body: body}, nil
		}
	}
	return plugin.Manifest{
		ID: "notes", Name: "Notes", Version: "1",
		Permissions: []plugin.Permission{{Name: "notes.secret", Description: "secret"}},
		Web: []plugin.WebRoute{
			{Path: "/", Nav: "Notes", Handle: page("Notes")},
			{Path: "/secret", AnyOf: []string{"notes.secret"}, Handle: page("Secret")},
			{Path: "/boom", Handle: func(*http.Request, plugin.WebSession) (plugin.WebPage, error) { panic("plugin bug") }},
			{Path: "/missing", Handle: func(*http.Request, plugin.WebSession) (plugin.WebPage, error) {
				return plugin.WebPage{}, plugin.ErrWebNotFound
			}},
		},
	}
}
func (notesPlugin) Init(context.Context, *plugin.Host) error { return nil }

type env struct {
	srv      *Server
	h        http.Handler
	sessions *websess.Service
	alice    int64
	admin    int64
}

func setup(t *testing.T, insecure bool) *env {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "web.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	ps := perm.NewService(db, perm.NewRegistry(), nil, log)
	as := auth.NewService(db, ps, "new", nil, log)
	cat, _ := theme.Builtin()
	reg, err := plugin.Load(ctx, plugin.Deps{DB: db, Perms: ps, Auth: as, Events: events.New(log), Log: log}, notesPlugin{})
	if err != nil {
		t.Fatal(err)
	}
	newUser := func(code, name string) int64 {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		s, _ := ssh.NewSignerFromKey(priv)
		u, err := as.Register(ctx, code, auth.Registration{Username: name, Password: "a long enough test passphrase",
			PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))})
		if err != nil {
			t.Fatal(err)
		}
		return u.ID
	}
	code, _ := as.CreateBootstrapInvite(ctx)
	admin := newUser(code, "admin1")
	inv, _, _ := as.CreateInvite(ctx, admin, auth.InviteOptions{})
	alice := newUser(inv, "alice")
	sessions := websess.NewService(db, as, nil, log)
	srv, err := New(Config{
		Log: log, SiteName: func(context.Context) string { return "Test BBS" }, Auth: as, Perms: ps, Sessions: sessions,
		Prefs: prefs.NewService(db, cat, nil), Themes: cat, Plugins: reg, SSHAddress: "bbs.example.net:2222",
		HostKeyFingerprint: "SHA256:testfingerprint", InviteUser: "new", InsecureCookies: insecure, ChatDays: 90, AuditDays: 365, GraceDays: 14,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &env{srv: srv, h: srv.Handler(), sessions: sessions, alice: alice, admin: admin}
}

type req struct {
	method, path string
	form         url.Values
	origin       string
	cookie       *http.Cookie
	headers      map[string]string
}

func (e *env) do(r req) *httptest.ResponseRecorder {
	var body *strings.Reader
	if r.form != nil {
		body = strings.NewReader(r.form.Encode())
	} else {
		body = strings.NewReader("")
	}
	q := httptest.NewRequest(r.method, "http://bbs.example.net"+r.path, body)
	if r.form != nil {
		q.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if r.origin != "" {
		q.Header.Set("Origin", r.origin)
	}
	if r.cookie != nil {
		q.AddCookie(r.cookie)
	}
	for k, v := range r.headers {
		q.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, q)
	return rec
}

func (e *env) login(t *testing.T, user int64, name string) *http.Cookie {
	t.Helper()
	code, _, err := e.sessions.NewCode(context.Background(), user)
	if err != nil {
		t.Fatal(err)
	}
	rec := e.do(req{method: "POST", path: "/login", origin: "https://bbs.example.net", form: url.Values{"username": {name}, "code": {code}}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Result().Cookies()[0]
}

func TestSecurityHeadersEverywhere(t *testing.T) {
	e := setup(t, false)
	for _, p := range []string{"/", "/privacy", "/login", "/nope", "/.well-known/gpc.json", "/version"} {
		rec := e.do(req{method: "GET", path: p})
		h := rec.Header()
		if h.Get("Content-Security-Policy") != ContentSecurityPolicy || h.Get("Referrer-Policy") != "same-origin" ||
			h.Get("X-Content-Type-Options") != "nosniff" || h.Get("X-Frame-Options") != "DENY" ||
			!strings.Contains(h.Get("Strict-Transport-Security"), "max-age=") {
			t.Errorf("%s: missing security headers: %v", p, h)
		}
	}
	if h := setup(t, true).do(req{method: "GET", path: "/"}).Header(); h.Get("Strict-Transport-Security") != "" {
		t.Error("HSTS sent in insecure (local test) mode")
	}
}

func TestGPC(t *testing.T) {
	e := setup(t, false)
	rec := e.do(req{method: "GET", path: "/.well-known/gpc.json"})
	var decl map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decl); err != nil || decl["gpc"] != true || decl["lastUpdate"] != GPCLastUpdate {
		t.Errorf("gpc.json = %s, %v", rec.Body.String(), err)
	}
	with := e.do(req{method: "GET", path: "/", headers: map[string]string{"Sec-GPC": "1"}})
	without := e.do(req{method: "GET", path: "/"})
	if !strings.Contains(with.Body.String(), "sent a Global Privacy Control signal") || strings.Contains(without.Body.String(), "sent a Global Privacy Control signal") {
		t.Error("Sec-GPC not acknowledged (or acknowledged without it)")
	}
	if !strings.Contains(with.Header().Get("Vary"), "Sec-GPC") {
		t.Error("missing Vary: Sec-GPC")
	}
	if p := e.do(req{method: "GET", path: "/privacy"}).Body.String(); !strings.Contains(p, "Global Privacy Control") || !strings.Contains(p, "14 days") {
		t.Error("privacy policy does not describe GPC or the configured retention")
	}
}

// TestNoThirdPartyRequests: pages only load resources from this server.
func TestNoThirdPartyRequests(t *testing.T) {
	e := setup(t, false)
	cookie := e.login(t, e.alice, "alice")
	resource := regexp.MustCompile(`(?i)<(?:script|img|link|iframe|audio|video|source)[^>]*(?:src|href)="([^"]+)"`)
	for _, p := range []string{"/", "/privacy", "/login", "/home", "/p/notes/"} {
		body := e.do(req{method: "GET", path: p, cookie: cookie}).Body.String()
		for _, m := range resource.FindAllStringSubmatch(body, -1) {
			if !strings.HasPrefix(m[1], "/") || strings.HasPrefix(m[1], "//") {
				t.Errorf("%s loads %q from elsewhere", p, m[1])
			}
		}
		if strings.Contains(body, "style=") || strings.Contains(body, "<style") || regexp.MustCompile(`<script>`).MatchString(body) {
			t.Errorf("%s has inline style or script (blocked by the CSP)", p)
		}
	}
}

func TestStaticAssets(t *testing.T) {
	e := setup(t, false)
	body := e.do(req{method: "GET", path: "/"}).Body.String()
	css := regexp.MustCompile(`href="(/static/app\.[0-9a-f]{12}\.css)"`).FindStringSubmatch(body)
	if css == nil {
		t.Fatalf("no fingerprinted stylesheet in %s", body)
	}
	rec := e.do(req{method: "GET", path: css[1]})
	if rec.Code != 200 || !strings.Contains(rec.Header().Get("Cache-Control"), "immutable") || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/css") {
		t.Errorf("asset = %d %v", rec.Code, rec.Header())
	}
	if rec := e.do(req{method: "GET", path: "/static/app.css"}); rec.Code != 404 {
		t.Error("unfingerprinted asset name served")
	}
}

func TestHomeAndVersion(t *testing.T) {
	e := setup(t, false)
	body := e.do(req{method: "GET", path: "/"}).Body.String()
	for _, want := range []string{"ssh -p 2222 YOUR-USERNAME@bbs.example.net", "SHA256:testfingerprint", "<code>new</code>", "Powered by shellshawk", version.Get().Version} {
		if !strings.Contains(body, want) {
			t.Errorf("home missing %q", want)
		}
	}
	rec := e.do(req{method: "GET", path: "/version"})
	var v version.Info
	if json.Unmarshal(rec.Body.Bytes(), &v); v != version.Get() || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("/version = %s", rec.Body.String())
	}
}

func TestLoginFlow(t *testing.T) {
	e := setup(t, false)
	good := func() url.Values {
		code, _, _ := e.sessions.NewCode(context.Background(), e.alice)
		return url.Values{"username": {"alice"}, "code": {code}}
	}
	tests := []struct {
		name   string
		form   url.Values
		origin string
		want   int
	}{
		{"no origin", good(), "", http.StatusForbidden},
		{"cross origin", good(), "https://evil.example", http.StatusForbidden},
		{"bad code", url.Values{"username": {"alice"}, "code": {"AAAA-AAAA"}}, "https://bbs.example.net", http.StatusUnauthorized},
		{"good code", good(), "https://bbs.example.net", http.StatusSeeOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.do(req{method: "POST", path: "/login", origin: tt.origin, form: tt.form})
			if rec.Code != tt.want {
				t.Fatalf("status = %d, want %d", rec.Code, tt.want)
			}
			if tt.want != http.StatusSeeOther {
				return
			}
			c := rec.Result().Cookies()[0]
			if c.Name != "__Host-session" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/" {
				t.Errorf("cookie = %+v", c)
			}
		})
	}

	// Rate limit: after 5 bad codes for alice even a good one is refused.
	for range loginUserFailures {
		e.do(req{method: "POST", path: "/login", origin: "https://bbs.example.net", form: url.Values{"username": {"alice"}, "code": {"BAD0-BAD0"}}})
	}
	if rec := e.do(req{method: "POST", path: "/login", origin: "https://bbs.example.net", form: good()}); rec.Code != http.StatusTooManyRequests {
		t.Errorf("rate limited login = %d", rec.Code)
	}
	if c := setup(t, true).login(t, 2, "alice"); c.Name != "session" || c.Secure {
		t.Errorf("insecure-mode cookie = %+v", c)
	}
}

func TestPluginPagesAndLogout(t *testing.T) {
	e := setup(t, false)
	if rec := e.do(req{method: "GET", path: "/p/notes/"}); rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Errorf("anonymous plugin page = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	cookie := e.login(t, e.alice, "alice")
	home := e.do(req{method: "GET", path: "/home", cookie: cookie}).Body.String()
	if !strings.Contains(home, `<a href="/p/notes/">Notes</a>`) || !strings.Contains(home, "Log out alice") {
		t.Errorf("dashboard nav missing: %s", home)
	}
	page := e.do(req{method: "GET", path: "/p/notes/", cookie: cookie})
	body := page.Body.String()
	if page.Code != 200 || !strings.Contains(body, "Hello &lt;script&gt;") || strings.Contains(body, "<script>alert") || strings.Contains(body, `href="javascript:`) {
		t.Errorf("plugin page not escaped/sanitised: %s", body)
	}
	if page.Header().Get("Cache-Control") != "no-store" {
		t.Error("private page cacheable")
	}
	for path, want := range map[string]int{"/p/notes/secret": 404, "/p/notes/missing": 404, "/p/notes/boom": 500} {
		if rec := e.do(req{method: "GET", path: path, cookie: cookie}); rec.Code != want || strings.Contains(rec.Body.String(), "plugin bug") {
			t.Errorf("%s = %d, want %d", path, rec.Code, want)
		}
	}
	admin := e.login(t, e.admin, "admin1")
	if rec := e.do(req{method: "GET", path: "/p/notes/secret", cookie: admin}); rec.Code != 200 {
		t.Errorf("admin secret page = %d", rec.Code)
	}

	// Logout needs the CSRF token.
	if rec := e.do(req{method: "POST", path: "/logout", cookie: cookie, origin: "https://bbs.example.net", form: url.Values{"csrf": {"wrong"}}}); rec.Code != http.StatusForbidden {
		t.Errorf("logout without token = %d", rec.Code)
	}
	csrf := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(home)[1]
	rec := e.do(req{method: "POST", path: "/logout", cookie: cookie, origin: "https://bbs.example.net", form: url.Values{"csrf": {csrf}}})
	if rec.Code != http.StatusSeeOther || rec.Result().Cookies()[0].MaxAge >= 0 {
		t.Errorf("logout = %d %+v", rec.Code, rec.Result().Cookies())
	}
	if rec := e.do(req{method: "GET", path: "/home", cookie: cookie}); rec.Code != http.StatusSeeOther {
		t.Error("session still valid after logout")
	}
}

func TestAccessLogPrivacy(t *testing.T) {
	var logBuf bytes.Buffer
	e := setup(t, false)
	h := withRequestLog(slog.New(slog.NewTextHandler(&logBuf, nil)), e.h)
	q := httptest.NewRequest("GET", "/?token=secret", nil)
	q.Header.Set("User-Agent", "agent-marker")
	h.ServeHTTP(httptest.NewRecorder(), q)
	for _, leak := range []string{"secret", "agent-marker", q.RemoteAddr} {
		if strings.Contains(logBuf.String(), leak) {
			t.Errorf("access log contains %q", leak)
		}
	}
}
