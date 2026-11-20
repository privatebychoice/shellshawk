package motd

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"net/http"

	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// run shows the message; members with motd.edit can also edit or clear it.
func (p *Plugin) run(ctx context.Context, s plugin.Session) error {
	for {
		m, err := p.Get(ctx)
		if err != nil {
			return err
		}
		set, err := s.Permissions(ctx)
		if err != nil {
			return err
		}
		if !set.Has(PermEdit) {
			if m.Body == "" {
				return tui.Message(ctx, s.UI(), s.Title("Message of the day"), "There is no message of the day.")
			}
			return s.UI().Show(ctx, p.page(s, m))
		}

		items := []tui.MenuItem{}
		if m.Body != "" {
			items = append(items, tui.MenuItem{Value: "show", Label: "Read the message of the day"},
				tui.MenuItem{Value: "edit", Label: "Edit the message of the day"},
				tui.MenuItem{Value: "clear", Label: "Remove the message of the day"})
		} else {
			items = append(items, tui.MenuItem{Value: "edit", Label: "Write a message of the day"})
		}
		intro := "There is no message of the day."
		if m.Body != "" {
			intro = "Members see the message once after logging in, and again whenever it changes."
		}
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Message of the day"), Intro: intro, Items: items})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "show":
			err = s.UI().Show(ctx, p.page(s, m))
		case "edit":
			err = p.edit(ctx, s, m.Body)
		case "clear":
			ok, cerr := tui.Confirm(ctx, s.UI(), s.Title("Message of the day"), "Remove the message of the day?")
			if cerr != nil || !ok {
				err = cerr
				break
			}
			err = p.Set(ctx, s.UserID(), "")
		}
		if errors.Is(err, tui.ErrCancelled) {
			err = nil
		}
		if err != nil {
			return err
		}
	}
}

// edit opens the editor with the current message and saves the result.
func (p *Plugin) edit(ctx context.Context, s plugin.Session, current string) error {
	body, err := s.UI().Edit(ctx, tui.EditRequest{
		Title:  s.Title("Message of the day"),
		Text:   current,
		MaxLen: MaxBody,
		Preview: func(text string) tui.Page {
			return s.Markdown(s.Title("Preview"), text)
		},
	})
	if err != nil {
		return err
	}
	if err := p.Set(ctx, s.UserID(), body); errors.Is(err, ErrInvalid) {
		return tui.Message(ctx, s.UI(), s.Title("Message of the day"), "Not saved. "+tui.Sentence(err, ErrInvalid))
	} else if err != nil {
		return err
	}
	return tui.Message(ctx, s.UI(), s.Title("Message of the day"), "Saved. Members will see it the next time they log in.")
}

var homeTmpl = template.Must(template.New("motd").Parse(`<section class="motd" aria-labelledby="motd-heading">
<h2 id="motd-heading">Message of the day</h2>
{{.Body}}
<p class="meta">Updated {{.When}}{{if .By}} by {{.By}}{{end}}.</p>
</section>`))

// webHome shows the message on the web home page.
func (p *Plugin) webHome(r *http.Request, s plugin.WebSession) (template.HTML, error) {
	m, err := p.Get(r.Context())
	if err != nil || m.Body == "" {
		return "", err
	}
	var b bytes.Buffer
	// The member's headings sit under the panel's <h2>.
	err = homeTmpl.Execute(&b, map[string]any{
		"Body": s.MarkdownAt(m.Body, 3), "When": m.UpdatedAt.UTC().Format("2006-01-02 15:04 UTC"), "By": m.UpdatedBy,
	})
	return template.HTML(b.String()), err //nolint:gosec // html/template output
}
