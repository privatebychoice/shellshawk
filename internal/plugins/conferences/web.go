package conferences

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
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
{{range .Posts}}<article class="post"><h2>Post {{.N}} by {{.Author}}</h2><p class="meta">{{.Date}}{{if .Edited}} (edited){{end}}</p>{{.Body}}{{range .Polls}}{{.}}{{end}}</article>{{end}}
{{.Chat}}{{end}}
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
		{Path: "/", AnyOf: []string{PermRead}, Handle: p.webAreas},
		{Path: "/c/{id}", AnyOf: []string{PermRead}, Handle: p.webConference},
		{Path: "/t/{id}", AnyOf: []string{PermRead}, Handle: p.webThread},
		{Path: "/t/{id}/poll/{poll}", Method: http.MethodPost, AnyOf: []string{PermRead}, Handle: p.webVote},
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
		N            int
		Author, Date string
		Edited       bool
		Body         template.HTML
		Polls        []template.HTML
	}
	var ps []postOut
	for i, po := range posts {
		out := postOut{N: i + 1, Author: po.Author, Date: po.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"), Edited: po.EditedAt != nil,
			Body: s.MarkdownAt(po.Body, 3)} // under the post's <h2>
		for _, pid := range po.Polls {
			if p.polls == nil {
				break
			}
			// The question is an <h3> under the post's <h2>.
			panel, err := p.polls.WebPanel(r.Context(), s.UserID(), pid, 3, s.Path(fmt.Sprintf("/t/%d/poll/%d", id, pid)), s.CSRF())
			if err != nil {
				return plugin.WebPage{}, err
			}
			out.Polls = append(out.Polls, panel)
		}
		ps = append(ps, out)
	}
	var chatPanel template.HTML
	if t.ChatChannelID != 0 && p.chat != nil {
		chatPanel, err = p.chat.WebPanel(r.Context(), s.UserID(), t.ChatChannelID, "Thread chat", s.CSRF(), s.Path("/t/"+strconv.FormatInt(id, 10)))
		if err != nil {
			return plugin.WebPage{}, err
		}
	}
	body, err := execTmpl("thread", map[string]any{
		"Conf": c.Name, "ConfHref": s.Path("/c/" + strconv.FormatInt(c.ID, 10)), "Locked": t.Locked, "Posts": ps, "Chat": chatPanel,
	})
	return plugin.WebPage{Title: t.Title, Body: body}, err
}

// webVote records a vote in a poll attached to a post in this thread. The
// thread check is what keeps polls in conferences the member cannot read
// out of reach: the poll must belong to one of the thread's posts.
func (p *Plugin) webVote(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	id, err := pathID(r)
	if err != nil {
		return plugin.WebPage{}, err
	}
	pid, err := strconv.ParseInt(r.PathValue("poll"), 10, 64)
	if err != nil || p.polls == nil {
		return plugin.WebPage{}, plugin.ErrWebNotFound
	}
	if _, _, _, err := p.Thread(r.Context(), s.UserID(), id); err != nil {
		return plugin.WebPage{}, webErr(err)
	}
	posts, err := p.Posts(r.Context(), s.UserID(), id)
	if err != nil {
		return plugin.WebPage{}, webErr(err)
	}
	if !slices.ContainsFunc(posts, func(po Post) bool { return slices.Contains(po.Polls, pid) }) {
		return plugin.WebPage{}, plugin.ErrWebNotFound
	}
	if err := p.polls.WebVote(r, s.UserID(), pid); err != nil {
		return plugin.WebPage{}, err
	}
	return plugin.WebPage{Redirect: s.Path(fmt.Sprintf("/t/%d#poll-%d", id, pid))}, nil
}
