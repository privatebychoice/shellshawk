// Package web serves the optional web interface (docs/DESIGN.md §11): a
// public start page with connection instructions, the privacy policy, GPC
// declaration, login with one-time codes from the TUI, and pages, actions
// and live streams contributed by plugins. Everything is self-hosted; pages make no
// third-party requests.
package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	ttemplate "text/template"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/markdown"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/prefs"
	"go.privatebychoice.com/shellshawk/internal/sessions"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/version"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Server-side timeouts bound slow or idle clients.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	maxFormBytes      = 4 << 10
)

// GPCLastUpdate is the lastUpdate date in /.well-known/gpc.json. Change it
// whenever the GPC declaration or its interpretation changes.
const GPCLastUpdate = "2026-11-16"

// Config configures the web interface.
type Config struct {
	Log      *slog.Logger
	SiteName func(ctx context.Context) string
	Auth     *auth.Service
	Perms    *perm.Service
	Sessions *websess.Service
	Prefs    *prefs.Service
	Themes   *theme.Catalog
	Plugins  *plugin.Registry // may be nil
	Grader   markdown.Grader  // may be nil
	// Connections lists and ends SSH connections (Who is online); nil
	// leaves the pages out.
	Connections *sessions.Service

	// SSHAddress is the public host:port members connect to, shown on the
	// start page (optional).
	SSHAddress string
	// HostKeyFingerprint is the SSH host key fingerprint shown on the start
	// page so members can verify it (optional).
	HostKeyFingerprint string
	InviteUser         string
	// InsecureCookies drops the Secure cookie attribute and HSTS, for local
	// testing over plain HTTP. Never set it in production.
	InsecureCookies bool
	// PrivacyPolicyFile replaces the built-in privacy policy with a
	// markdown file (optional).
	PrivacyPolicyFile string
	// Retention figures quoted in the built-in privacy policy.
	ChatDays, AuditDays, GraceDays int
}

// Server is the web interface.
type Server struct {
	cfg     Config
	log     *slog.Logger
	tmpl    *template.Template
	assets  *assetStore
	policy  string // privacy policy markdown, possibly a template
	custom  bool   // policy came from PrivacyPolicyFile
	ipLim   *auth.Limiter
	userLim *auth.Limiter
	streams *streams
	handler http.Handler
}

// Login rate limits.
const (
	loginIPFailures   = 10
	loginUserFailures = 5
	loginWindow       = 15 * time.Minute
)

// New builds the web interface.
func New(cfg Config) (*Server, error) {
	if cfg.Log == nil || cfg.SiteName == nil || cfg.Auth == nil || cfg.Perms == nil || cfg.Sessions == nil || cfg.Prefs == nil || cfg.Themes == nil {
		return nil, errors.New("web: incomplete configuration")
	}
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, fmt.Errorf("web: templates: %w", err)
	}
	assets, err := loadAssets(cfg.Themes)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, log: cfg.Log.With("component", "web"), tmpl: tmpl, assets: assets,
		ipLim:   auth.NewLimiter(loginIPFailures, loginWindow, nil),
		userLim: auth.NewLimiter(loginUserFailures, loginWindow, nil),
		streams: newStreams(),
	}
	if cfg.PrivacyPolicyFile != "" {
		b, err := os.ReadFile(cfg.PrivacyPolicyFile)
		if err != nil {
			return nil, fmt.Errorf("web: privacy policy: %w", err)
		}
		s.policy, s.custom = string(b), true
	} else {
		b, err := files.ReadFile("templates/privacy.md")
		if err != nil {
			return nil, err
		}
		s.policy = string(b)
	}
	s.handler = s.routes()
	return s, nil
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.handler }

// NewHTTPServer wraps a handler with the server-side timeouts.
func NewHTTPServer(addr string, h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: readHeaderTimeout, ReadTimeout: readTimeout, WriteTimeout: writeTimeout, IdleTimeout: idleTimeout,
		ErrorLog: slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /version", handleVersion)
	mux.HandleFunc("GET /.well-known/gpc.json", handleGPC)
	mux.HandleFunc("GET /static/{file}", s.handleStatic)
	mux.HandleFunc("GET /{$}", s.handleHome)
	mux.HandleFunc("GET /privacy", s.handlePrivacy)
	mux.HandleFunc("GET /login", s.handleLoginForm)
	mux.HandleFunc("POST /login", s.handleLogin)
	mux.HandleFunc("POST /logout", s.handleLogout)
	mux.HandleFunc("GET /home", s.handleDashboard)
	if s.cfg.Connections != nil {
		mux.HandleFunc("GET /admin/online", s.handleOnline)
		mux.HandleFunc("GET /admin/online/{id}", s.handleOnlineConfirm)
		mux.HandleFunc("POST /admin/online/{id}/end", s.handleOnlineEnd)
		mux.HandleFunc("GET /admin/web-sessions/{id}", s.handleWebSessionConfirm)
		mux.HandleFunc("POST /admin/web-sessions/{id}/end", s.handleWebSessionEnd)
	}
	if s.cfg.Plugins != nil {
		for _, p := range s.cfg.Plugins.Plugins() {
			for _, r := range p.Manifest.Web {
				method := r.Method
				if method == "" {
					method = http.MethodGet
				}
				pattern := method + " /p/" + p.Manifest.ID + r.Path
				if r.Path == "/" {
					pattern += "{$}"
				}
				if r.Stream != nil {
					mux.Handle(pattern, s.pluginStream(p.Manifest.ID, r))
				} else {
					mux.Handle(pattern, s.pluginPage(p.Manifest.ID, r))
				}
			}
		}
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.renderError(w, r, http.StatusNotFound, "Page not found.")
	})
	return withRequestLog(s.log, securityHeaders(!s.cfg.InsecureCookies, gpcSignal(sameOrigin(s.withSession(mux)))))
}

// ---- middleware --------------------------------------------------------------

type ctxKey int

const (
	keyLogger ctxKey = iota
	keyGPC
	keySession
)

// LoggerFrom returns the request-scoped logger (carrying request_id), or the
// default logger outside a request.
func LoggerFrom(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(keyLogger).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

// statusRecorder captures the response status for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// withRequestLog assigns each request a random ID (returned in X-Request-ID)
// and writes one access-log line per request.
//
// Privacy: the log records method, path (no query string), status and
// duration only — never client IPs, user agents, cookies or query values.
func withRequestLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := newRequestID()
		rl := log.With("request_id", id)
		w.Header().Set("X-Request-ID", id)
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), keyLogger, rl)))
		level := slog.LevelInfo
		if rec.status >= 500 {
			level = slog.LevelError
		}
		rl.Log(r.Context(), level, "http request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ContentSecurityPolicy allows only this server's own scripts, styles,
// images and live connections (server-sent events), with no inline code. It is strict without blanket bans such as
// style-src 'none' that would break extension-injected placeholders
// (Privacy Badger).
const ContentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
	"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

func securityHeaders(secure bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", ContentSecurityPolicy)
		// same-origin, not no-referrer: under no-referrer browsers send
		// "Origin: null" on same-origin form POSTs, which sameOrigin must
		// refuse. Other sites still receive no referrer, and links in posts
		// also carry rel="noreferrer".
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=(), browsing-topics=()")
		if secure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// gpcSignal records the Sec-GPC request header. Nothing is sold or shared,
// so there is nothing to switch off; the signal is acknowledged on the page.
func gpcSignal(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Sec-GPC")
		gpc := strings.TrimSpace(r.Header.Get("Sec-GPC")) == "1"
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), keyGPC, gpc)))
	})
}

// sameOrigin rejects state-changing requests whose Origin (or, failing
// that, Referer) is not this site, as defence in depth with SameSite
// cookies and CSRF tokens.
func sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		src := r.Header.Get("Origin")
		if src == "" || src == "null" {
			src = r.Header.Get("Referer")
		}
		u, err := url.Parse(src)
		if src == "" || err != nil || !strings.EqualFold(u.Host, r.Host) {
			LoggerFrom(r.Context()).Info("cross-origin request refused", "method", r.Method, "path", r.URL.Path)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cookieName() string {
	if s.cfg.InsecureCookies {
		return "session"
	}
	return "__Host-session" // requires Secure, Path=/ and no Domain
}

func (s *Server) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(s.cookieName()); err == nil {
			if sess, err := s.cfg.Sessions.Lookup(r.Context(), c.Value); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), keySession, &sess))
			}
		}
		next.ServeHTTP(w, r)
	})
}

func sessionFrom(r *http.Request) *websess.Session {
	sess, _ := r.Context().Value(keySession).(*websess.Session)
	return sess
}

// ---- rendering -----------------------------------------------------------------

type navItem struct{ Label, Href string }

type layoutData struct {
	Site, Title, Version, User, CSRF string
	Body                             template.HTML
	Nav                              []navItem
	GPC                              bool
	Assets                           Assets
}

func (s *Server) layout(r *http.Request, title string, body template.HTML) layoutData {
	d := layoutData{Site: s.cfg.SiteName(r.Context()), Title: title, Version: version.Get().Version, Body: body, Assets: s.assets.Default}
	d.GPC, _ = r.Context().Value(keyGPC).(bool)
	if sess := sessionFrom(r); sess != nil {
		d.CSRF = sess.CSRF
		if u, err := s.cfg.Auth.UserByID(r.Context(), sess.UserID); err == nil {
			d.User = u.Username
		}
		if p, err := s.cfg.Prefs.Get(r.Context(), sess.UserID); err == nil {
			d.Assets = s.assets.forTheme(p.Theme)
		}
		d.Nav = s.nav(r.Context(), sess.UserID)
	}
	return d
}

// nav lists the pages the member may open: plugin pages, then staff pages.
func (s *Server) nav(ctx context.Context, user int64) []navItem {
	set, err := s.cfg.Perms.Permissions(ctx, user)
	if err != nil {
		return nil
	}
	var out []navItem
	if s.cfg.Plugins != nil {
		for _, p := range s.cfg.Plugins.Plugins() {
			for _, r := range p.Manifest.Web {
				if r.Nav != "" && allowed(set, r.AnyOf) {
					out = append(out, navItem{Label: r.Nav, Href: "/p/" + p.Manifest.ID + r.Path})
				}
			}
		}
	}
	if s.cfg.Connections != nil && set.Has(perm.SessionsManage) {
		out = append(out, navItem{Label: "Who is online", Href: "/admin/online"})
	}
	return out
}

func allowed(set perm.Set, anyOf []string) bool {
	if len(anyOf) == 0 {
		return true
	}
	for _, p := range anyOf {
		if set.Has(p) {
			return true
		}
	}
	return false
}

func (s *Server) execute(name string, data any) (template.HTML, error) {
	var b bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&b, name, data); err != nil {
		return "", err
	}
	return template.HTML(b.String()), nil //nolint:gosec // output of html/template, already escaped
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, title, page string, data any) {
	body, err := s.execute(page, data)
	if err != nil {
		LoggerFrom(r.Context()).Error("render page", "page", page, "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	s.writePage(w, r, status, title, body)
}

func (s *Server) writePage(w http.ResponseWriter, r *http.Request, status int, title string, body template.HTML) {
	var b bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&b, "layout", s.layout(r, title, body)); err != nil {
		LoggerFrom(r.Context()).Error("render layout", "err", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(b.Bytes())
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.render(w, r, status, http.StatusText(status), "error", map[string]string{"Message": msg})
}

// ---- handlers ------------------------------------------------------------------

func handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(version.Get()); err != nil {
		LoggerFrom(r.Context()).Warn("write /version response", "err", err)
	}
}

func handleGPC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_ = json.NewEncoder(w).Encode(map[string]any{"gpc": true, "lastUpdate": GPCLastUpdate})
}

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	a, ok := s.assets.byPath["/static/"+r.PathValue("file")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable") // names change with content
	_, _ = w.Write(a.data)
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	d := map[string]any{"Site": s.cfg.SiteName(r.Context()), "HostKey": s.cfg.HostKeyFingerprint, "InviteUser": s.cfg.InviteUser}
	if host, port, err := net.SplitHostPort(s.cfg.SSHAddress); err == nil && host != "" {
		d["SSHAddress"], d["SSHHost"], d["SSHPort"] = s.cfg.SSHAddress, host, port
	}
	s.render(w, r, http.StatusOK, "Welcome", "home", d)
}

func (s *Server) handlePrivacy(w http.ResponseWriter, r *http.Request) {
	src := s.policy
	if !s.custom {
		var b strings.Builder
		t, err := ttemplate.New("policy").Parse(s.policy)
		if err == nil {
			err = t.Execute(&b, map[string]any{
				"Site": s.cfg.SiteName(r.Context()), "ChatDays": s.cfg.ChatDays, "AuditDays": s.cfg.AuditDays, "GraceDays": s.cfg.GraceDays,
			})
		}
		if err != nil {
			LoggerFrom(r.Context()).Error("privacy policy template", "err", err)
			s.renderError(w, r, http.StatusInternalServerError, "The privacy policy could not be shown.")
			return
		}
		src = b.String()
	}
	html, err := markdown.RenderHTML(src, s.cfg.Grader, markdown.UnderTitle)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "The privacy policy could not be shown.")
		return
	}
	s.writePage(w, r, http.StatusOK, "Privacy", template.HTML(html)) //nolint:gosec // sanitising markdown renderer
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if sessionFrom(r) != nil {
		http.Redirect(w, r, "/home", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "Log in", "login", map[string]string{})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		s.renderError(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	username := auth.NormalizeUsername(r.PostForm.Get("username"))
	code := r.PostForm.Get("code")
	ipKey, userKey := "ip:"+clientIP(r), "user:"+username
	fail := func(status int, msg string) {
		s.render(w, r, status, "Log in", "login", map[string]string{"Error": msg, "Username": username})
	}
	if s.ipLim.Blocked(ipKey) || s.userLim.Blocked(userKey) {
		LoggerFrom(r.Context()).Info("web login rate-limited")
		fail(http.StatusTooManyRequests, "Too many failed attempts. Please wait a few minutes and get a new code.")
		return
	}
	uid, err := s.cfg.Sessions.Redeem(r.Context(), username, code)
	if err != nil {
		s.ipLim.Fail(ipKey)
		s.userLim.Fail(userKey)
		LoggerFrom(r.Context()).Info("web login refused")
		fail(http.StatusUnauthorized, "That username and code did not work. Codes work once and expire after five minutes.")
		return
	}
	tok, sess, err := s.cfg.Sessions.Create(r.Context(), uid)
	if err != nil {
		LoggerFrom(r.Context()).Error("create web session", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "You could not be logged in. Please try again.")
		return
	}
	s.ipLim.Reset(ipKey)
	s.userLim.Reset(userKey)
	http.SetCookie(w, &http.Cookie{
		Name: s.cookieName(), Value: tok, Path: "/", Expires: sess.ExpiresAt,
		HttpOnly: true, Secure: !s.cfg.InsecureCookies, SameSite: http.SameSiteStrictMode,
	})
	LoggerFrom(r.Context()).Info("web login", "user_id", uid)
	http.Redirect(w, r, "/home", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess := sessionFrom(r)
	if sess == nil || r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return
	}
	if c, err := r.Cookie(s.cookieName()); err == nil {
		_ = s.cfg.Sessions.Delete(r.Context(), c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: !s.cfg.InsecureCookies, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	d := s.layout(r, "Home", "")
	s.render(w, r, http.StatusOK, "Home", "dashboard", map[string]any{"User": d.User, "Nav": d.Nav, "Panels": s.homePanels(r, sess)})
}

// homePanels collects plugin panels for the home page (WebHome). A failing
// plugin is logged and left out rather than breaking the page.
func (s *Server) homePanels(r *http.Request, sess *websess.Session) []template.HTML {
	if s.cfg.Plugins == nil {
		return nil
	}
	set, err := s.cfg.Perms.Permissions(r.Context(), sess.UserID)
	if err != nil {
		LoggerFrom(r.Context()).Error("home panels: permissions", "err", err)
		return nil
	}
	var out []template.HTML
	for _, p := range s.cfg.Plugins.Plugins() {
		if p.Manifest.WebHome == nil || !pluginVisible(set, p.Manifest) {
			continue
		}
		ws := webSession{s: s, user: sess.UserID, plugin: p.Manifest.ID, csrf: sess.CSRF}
		html, err := safeHome(p.Manifest.WebHome, r, ws)
		if err != nil {
			LoggerFrom(r.Context()).Error("home panel failed", "plugin", p.Manifest.ID, "err", err)
			continue
		}
		if html != "" {
			out = append(out, html)
		}
	}
	return out
}

// pluginVisible: a home panel is shown to members who may use at least one
// of the plugin's menu items or pages (or any member if it has neither).
func pluginVisible(set perm.Set, m plugin.Manifest) bool {
	gated := false
	for _, it := range m.MenuItems {
		gated = true
		if allowed(set, it.AnyOf) {
			return true
		}
	}
	for _, r := range m.Web {
		gated = true
		if allowed(set, r.AnyOf) {
			return true
		}
	}
	return !gated
}

func safeHome(fn func(*http.Request, plugin.WebSession) (template.HTML, error), r *http.Request, ws plugin.WebSession) (html template.HTML, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("panic: %v", rec)
		}
	}()
	return fn(r, ws)
}

// webSession is the member as seen by plugin pages.
type webSession struct {
	s      *Server
	user   int64
	plugin string
	csrf   string
}

func (ws webSession) UserID() int64 { return ws.user }
func (ws webSession) Permissions(ctx context.Context) (perm.Set, error) {
	return ws.s.cfg.Perms.Permissions(ctx, ws.user)
}
func (ws webSession) Markdown(src string) template.HTML {
	return ws.MarkdownAt(src, markdown.UnderTitle)
}

func (ws webSession) MarkdownAt(src string, level int) template.HTML {
	html, err := markdown.RenderHTML(src, ws.s.cfg.Grader, level)
	if err != nil {
		return template.HTML("<p>This content could not be shown.</p>")
	}
	return template.HTML(html) //nolint:gosec // sanitising markdown renderer
}
func (ws webSession) Path(rel string) string { return "/p/" + ws.plugin + rel }
func (ws webSession) CSRF() string           { return ws.csrf }

// pluginPage serves a plugin's page or POST action to logged-in members
// holding the route's permission. Pages the member may not open are
// reported as not found. POST actions need the session's CSRF token.
func (s *Server) pluginPage(id string, route plugin.WebRoute) http.Handler {
	post := route.Method == http.MethodPost
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r)
		if post {
			r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
			if sess == nil || r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
				s.pluginError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
				return
			}
		}
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		set, err := s.cfg.Perms.Permissions(r.Context(), sess.UserID)
		if err != nil || !allowed(set, route.AnyOf) {
			s.pluginError(w, r, http.StatusNotFound, "Page not found.")
			return
		}
		page, err := safeHandle(route, r, webSession{s: s, user: sess.UserID, plugin: id, csrf: sess.CSRF})
		var werr *plugin.WebError
		switch {
		case errors.Is(err, plugin.ErrWebNotFound):
			s.pluginError(w, r, http.StatusNotFound, "Page not found.")
		case errors.As(err, &werr) && werr.Status >= 400 && werr.Status < 500:
			s.pluginError(w, r, werr.Status, werr.Message)
		case err != nil:
			LoggerFrom(r.Context()).Error("plugin page failed", "plugin", id, "err", err)
			s.pluginError(w, r, http.StatusInternalServerError, "Sorry, something went wrong.")
		case post && page.Redirect == "" && page.Body != "":
			// A form shown again with its errors.
			s.writePage(w, r, http.StatusUnprocessableEntity, page.Title, page.Body)
		case post:
			http.Redirect(w, r, localPath(page.Redirect), http.StatusSeeOther)
		default:
			s.writePage(w, r, http.StatusOK, page.Title, page.Body)
		}
	})
}

// pluginError renders an error page, or plain text for scripts that ask
// for it (live.js), so they can show the message inline.
func (s *Server) pluginError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if strings.Contains(r.Header.Get("Accept"), "text/plain") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(msg))
		return
	}
	s.renderError(w, r, status, msg)
}

// localPath returns p if it is a plain path on this site, otherwise /home,
// so a plugin's redirect can never send the browser elsewhere.
func localPath(p string) string {
	u, err := url.Parse(p)
	if err != nil || !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n") ||
		u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/home"
	}
	return p
}

func safeHandle(route plugin.WebRoute, r *http.Request, ws plugin.WebSession) (page plugin.WebPage, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("panic: %v", rec)
		}
	}()
	return route.Handle(r, ws)
}
