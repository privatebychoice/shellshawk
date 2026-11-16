package conferences

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"strconv"

	"go.privatebychoice.com/shellshawk/internal/plugin"
)

var webTmpl = template.Must(template.New("conf").Parse(`
{{define "areas"}}{{range .}}<section><h2>{{.Area.Name}}</h2>{{if .Area.Description}}<p class="meta">{{.Area.Description}}</p>{{end}}
<ul class="list">{{range .Confs}}<li><a href="{{.Href}}">{{.Name}}</a>{{if .Description}} <span class="meta">{{.Description}}</span>{{end}}</li>{{end}}</ul></section>
{{else}}<p>There are no conferences you can read.</p>{{end}}{{end}}
{{define "threads"}}{{if .Description}}<p>{{.Description}}</p>{{end}}
{{if .Threads}}<ul class="list">{{range .Threads}}<li><a href="{{.Href}}">{{.Title}}</a>{{if .Locked}} (locked){{end}}
<span class="meta">by {{.Author}}, {{.Posts}} post(s), last {{.Last}}</span></li>{{end}}</ul>{{else}}<p>No threads yet.</p>{{end}}
<p class="meta">Start threads and reply over SSH.</p>{{end}}
{{define "thread"}}<p class="meta">In <a href="{{.ConfHref}}">{{.Conf}}</a>.{{if .Locked}} This thread is locked.{{end}}</p>
{{range .Posts}}<article class="post"><h2>Post {{.N}} by {{.Author}}</h2><p class="meta">{{.Date}}{{if .Edited}} (edited){{end}}{{if .Polls}} · has a poll: vote over SSH{{end}}</p>{{.Body}}</article>{{end}}{{end}}
`))

func execTmpl(name string, data any) (template.HTML, error) {
	var b bytes.Buffer
	if err := webTmpl.ExecuteTemplate(&b, name, data); err != nil {
		return "", err
	}
	return template.HTML(b.String()), nil //nolint:gosec // html/template output
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return 0, plugin.ErrWebNotFound
	}
	return id, nil
}

func webErr(err error) error {
	if errors.Is(err, ErrNotFound) {
		return plugin.ErrWebNotFound
	}
	return err
}

func (p *Plugin) webRoutes() []plugin.WebRoute {
	return []plugin.WebRoute{
		{Path: "/", Nav: "Conferences", AnyOf: []string{PermRead}, Handle: p.webAreas},
		{Path: "/c/{id}", AnyOf: []string{PermRead}, Handle: p.webConference},
		{Path: "/t/{id}", AnyOf: []string{PermRead}, Handle: p.webThread},
	}
}

func (p *Plugin) webAreas(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	areas, err := p.Areas(r.Context())
	if err != nil {
		return plugin.WebPage{}, err
	}
	type confLink struct{ Name, Description, Href string }
	type areaOut struct {
		Area  Area
		Confs []confLink
	}
	var out []areaOut
	for _, a := range areas {
		confs, err := p.Conferences(r.Context(), s.UserID(), a.ID)
		if err != nil {
			return plugin.WebPage{}, err
		}
		if len(confs) == 0 {
			continue
		}
		ao := areaOut{Area: a}
		for _, c := range confs {
			ao.Confs = append(ao.Confs, confLink{c.Name, c.Description, s.Path("/c/" + strconv.FormatInt(c.ID, 10))})
		}
		out = append(out, ao)
	}
	body, err := execTmpl("areas", out)
	return plugin.WebPage{Title: "Conferences", Body: body}, err
}

func (p *Plugin) webConference(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	id, err := pathID(r)
	if err != nil {
		return plugin.WebPage{}, err
	}
	c, _, err := p.access(r.Context(), s.UserID(), id)
	if err != nil {
		return plugin.WebPage{}, webErr(err)
	}
	threads, err := p.Threads(r.Context(), s.UserID(), id)
	if err != nil {
		return plugin.WebPage{}, webErr(err)
	}
	type threadOut struct {
		Title, Author, Href, Last string
		Posts                     int
		Locked                    bool
	}
	var ts []threadOut
	for _, t := range threads {
		ts = append(ts, threadOut{t.Title, t.Author, s.Path("/t/" + strconv.FormatInt(t.ID, 10)),
			t.LastPostAt.UTC().Format("2006-01-02 15:04 UTC"), t.Posts, t.Locked})
	}
	body, err := execTmpl("threads", map[string]any{"Description": c.Description, "Threads": ts})
	return plugin.WebPage{Title: c.Name, Body: body}, err
}

func (p *Plugin) webThread(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	id, err := pathID(r)
	if err != nil {
		return plugin.WebPage{}, err
	}
	t, c, _, err := p.Thread(r.Context(), s.UserID(), id)
	if err != nil {
		return plugin.WebPage{}, webErr(err)
	}
	posts, err := p.Posts(r.Context(), s.UserID(), id)
	if err != nil {
		return plugin.WebPage{}, webErr(err)
	}
	type postOut struct {
		N             int
		Author, Date  string
		Edited, Polls bool
		Body          template.HTML
	}
	var ps []postOut
	for i, po := range posts {
		ps = append(ps, postOut{i + 1, po.Author, po.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"), po.EditedAt != nil, len(po.Polls) > 0, s.Markdown(po.Body)})
	}
	body, err := execTmpl("thread", map[string]any{
		"Conf": c.Name, "ConfHref": s.Path("/c/" + strconv.FormatInt(c.ID, 10)), "Locked": t.Locked, "Posts": ps,
	})
	return plugin.WebPage{Title: t.Title, Body: body}, err
}
