package messages

import (
	"bytes"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/plugin"
)

var webTmpl = template.Must(template.New("msg").Parse(`
{{define "inbox"}}<p>{{.Counts.Unread}} unread, {{.Counts.Read}} read.</p>
{{if .Messages}}<ul class="list">{{range .Messages}}<li{{if not .Read}} class="unread"{{end}}>{{if not .Read}}New: {{end}}<a href="{{.Href}}">{{.Subject}}</a>
<span class="meta">from {{.From}}, {{.Date}}</span></li>{{end}}</ul>{{else}}<p>Your inbox is empty.</p>{{end}}
<p class="meta">Write and reply to messages over SSH.</p>{{end}}
{{define "message"}}<dl class="meta"><dt>From</dt><dd>{{.From}}</dd><dt>To</dt><dd>{{.To}}</dd><dt>Date</dt><dd>{{.Date}}</dd></dl>
<article class="post">{{.Body}}</article>
<p><a href="{{.Back}}">Back to the inbox</a></p>{{end}}
`))

func execTmpl(name string, data any) (template.HTML, error) {
	var b bytes.Buffer
	if err := webTmpl.ExecuteTemplate(&b, name, data); err != nil {
		return "", err
	}
	return template.HTML(b.String()), nil //nolint:gosec // html/template output
}

func (p *Plugin) webRoutes() []plugin.WebRoute {
	return []plugin.WebRoute{
		{Path: "/", Nav: "Messages", Handle: p.webInbox},
		{Path: "/m/{id}", Handle: p.webMessage},
	}
}

func (p *Plugin) webInbox(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	c, err := p.Count(r.Context(), s.UserID())
	if err != nil {
		return plugin.WebPage{}, err
	}
	list, err := p.List(r.Context(), s.UserID(), Inbox)
	if err != nil {
		return plugin.WebPage{}, err
	}
	type item struct {
		Subject, From, Date, Href string
		Read                      bool
	}
	var items []item
	for _, m := range list {
		items = append(items, item{m.Subject, m.From, fmtTime(m), s.Path("/m/" + strconv.FormatInt(m.ID, 10)), m.Read})
	}
	body, err := execTmpl("inbox", map[string]any{"Counts": c, "Messages": items})
	return plugin.WebPage{Title: "Messages", Body: body}, err
}

// webMessage shows a message the member sent or received. Opening a
// received message marks it read, as in the BBS.
func (p *Plugin) webMessage(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return plugin.WebPage{}, plugin.ErrWebNotFound
	}
	m, err := p.Read(r.Context(), s.UserID(), id)
	if errors.Is(err, ErrNotFound) {
		return plugin.WebPage{}, plugin.ErrWebNotFound
	}
	if err != nil {
		return plugin.WebPage{}, err
	}
	body, err := execTmpl("message", map[string]any{
		"From": m.From, "To": strings.Join(m.To, ", "), "Date": fmtTime(m.Summary), "Body": s.Markdown(m.Body), "Back": s.Path("/"),
	})
	return plugin.WebPage{Title: m.Subject, Body: body}, err
}
