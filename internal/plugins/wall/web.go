package wall

import (
	"bytes"
	"html/template"
	"net/http"

	"go.privatebychoice.com/shellshawk/internal/plugin"
)

var wallTmpl = template.Must(template.New("wall").Parse(`{{if .Lines}}<ul class="list wall">
{{range .Lines}}<li><strong>{{.User}}</strong>: {{.Text}} <span class="meta">({{.Age}})</span></li>
{{end}}</ul>{{else}}<p>The wall is empty.</p>{{end}}
<p class="meta">Lines disappear {{.Expiry}} after their last edit. Write or edit your line over SSH.</p>`))

func (p *Plugin) webRoutes() []plugin.WebRoute {
	return []plugin.WebRoute{{Path: "/", Handle: p.webWall}}
}

// webWall shows the wall (read-only).
func (p *Plugin) webWall(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	entries, err := p.Entries(r.Context())
	if err != nil {
		return plugin.WebPage{}, err
	}
	type lineOut struct {
		User, Age string
		Text      template.HTML
	}
	var lines []lineOut
	now := p.now()
	for _, e := range entries {
		// HTML escapes all text and adds only <strong> and <em>.
		lines = append(lines, lineOut{User: e.Username, Age: ago(now, e.UpdatedAt), Text: template.HTML(HTML(e.Text))}) //nolint:gosec // see HTML
	}
	var b bytes.Buffer
	if err := wallTmpl.Execute(&b, map[string]any{"Lines": lines, "Expiry": roughly(p.Expiry(r.Context()))}); err != nil {
		return plugin.WebPage{}, err
	}
	return plugin.WebPage{Title: "Wall", Body: template.HTML(b.String())}, nil //nolint:gosec // html/template output
}
