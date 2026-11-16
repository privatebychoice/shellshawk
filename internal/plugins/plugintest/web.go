package plugintest

import (
	"context"
	"html/template"
	"net/http/httptest"

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
	h, _ := markdown.RenderHTML(src, nil)
	return template.HTML(h) //nolint:gosec // sanitising renderer
}
func (w WebSession) Path(rel string) string { return "/p/" + w.Plugin + rel }

// WebGet calls the plugin route whose Path is pattern, with path values.
func (e *Env) WebGet(p plugin.Plugin, pattern string, values map[string]string, user int64) (plugin.WebPage, error) {
	e.t.Helper()
	m := p.Manifest()
	for _, r := range m.Web {
		if r.Path != pattern {
			continue
		}
		req := httptest.NewRequest("GET", "/p/"+m.ID+pattern, nil)
		for k, v := range values {
			req.SetPathValue(k, v)
		}
		return r.Handle(req, WebSession{Env: e, User: user, Plugin: m.ID})
	}
	e.t.Fatalf("no web route %s", pattern)
	return plugin.WebPage{}, nil
}
