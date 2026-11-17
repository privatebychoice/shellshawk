package plugintest

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/markdown"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
)

// WebSession is a plugin.WebSession for tests.
type WebSession struct {
	Env    *Env
	User   int64
	Plugin string
}

func (w WebSession) UserID() int64 { return w.User }
func (w WebSession) Permissions(ctx context.Context) (perm.Set, error) {
	return w.Env.Perms.Permissions(ctx, w.User)
}
func (w WebSession) Markdown(src string) template.HTML {
	return w.MarkdownAt(src, markdown.UnderTitle)
}
func (w WebSession) MarkdownAt(src string, level int) template.HTML {
	h, _ := markdown.RenderHTML(src, nil, level)
	return template.HTML(h) //nolint:gosec // sanitising renderer
}
func (w WebSession) Path(rel string) string { return "/p/" + w.Plugin + rel }
func (w WebSession) CSRF() string           { return "test-csrf" }

// route returns the plugin's web route with method and path pattern.
func (e *Env) route(p plugin.Plugin, method, pattern string) plugin.WebRoute {
	e.t.Helper()
	for _, r := range p.Manifest().Web {
		m := r.Method
		if m == "" {
			m = http.MethodGet
		}
		if r.Path == pattern && m == method {
			return r
		}
	}
	e.t.Fatalf("no web route %s %s", method, pattern)
	return plugin.WebRoute{}
}

func (e *Env) request(p plugin.Plugin, method, pattern string, values map[string]string, form url.Values) *http.Request {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, "/p/"+p.Manifest().ID+pattern, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range values {
		req.SetPathValue(k, v)
	}
	return req
}

// WebGet calls the plugin's GET page whose Path is pattern, with path values.
func (e *Env) WebGet(p plugin.Plugin, pattern string, values map[string]string, user int64) (plugin.WebPage, error) {
	e.t.Helper()
	r := e.route(p, http.MethodGet, pattern)
	return r.Handle(e.request(p, http.MethodGet, pattern, values, nil), WebSession{Env: e, User: user, Plugin: p.Manifest().ID})
}

// WebGetQuery is WebGet with a query string (e.g. a search form).
func (e *Env) WebGetQuery(p plugin.Plugin, pattern string, values map[string]string, query url.Values, user int64) (plugin.WebPage, error) {
	e.t.Helper()
	r := e.route(p, http.MethodGet, pattern)
	req := e.request(p, http.MethodGet, pattern, values, nil)
	req.URL.RawQuery = query.Encode()
	return r.Handle(req, WebSession{Env: e, User: user, Plugin: p.Manifest().ID})
}

// WebPost calls the plugin's POST action whose Path is pattern. The core's
// CSRF and origin checks are tested in the web package, not here.
func (e *Env) WebPost(p plugin.Plugin, pattern string, values map[string]string, form url.Values, user int64) (plugin.WebPage, error) {
	e.t.Helper()
	r := e.route(p, http.MethodPost, pattern)
	return r.Handle(e.request(p, http.MethodPost, pattern, values, form), WebSession{Env: e, User: user, Plugin: p.Manifest().ID})
}

// WebStream runs the plugin's stream whose Path is pattern until ctx is
// done, returning what it wrote. Run it in a goroutine and cancel ctx.
func (e *Env) WebStream(ctx context.Context, p plugin.Plugin, pattern string, values map[string]string, user int64) (*httptest.ResponseRecorder, error) {
	r := e.route(p, http.MethodGet, pattern)
	rec := httptest.NewRecorder()
	req := e.request(p, http.MethodGet, pattern, values, nil).WithContext(ctx)
	err := r.Stream(rec, req, WebSession{Env: e, User: user, Plugin: p.Manifest().ID})
	return rec, err
}
