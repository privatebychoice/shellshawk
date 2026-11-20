package polls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
)

// The web side lets members read polls, vote or change their vote, and see
// results under the same rules as over SSH. Creating, closing, pinning and
// deleting stay on SSH.

var webTmpl = template.Must(template.New("polls").Parse(`
{{define "list"}}{{if .Polls}}<ul class="list">{{range .Polls}}<li>{{if .Pinned}}Pinned: {{end}}<a href="{{.Href}}">{{.Question}}</a></li>{{end}}</ul>{{else}}<p>{{.Empty}}</p>{{end}}
<p><a href="{{.Other}}">{{.OtherLabel}}</a></p>
<p class="meta">Create, close and pin polls over SSH.</p>{{end}}

{{define "panel"}}<section class="poll" id="poll-{{.ID}}"{{if .Heading}} aria-labelledby="poll-{{.ID}}-q"{{end}}>
{{.Heading}}<p class="meta">{{.About}}</p>
{{- if .CanVote}}
<form method="post" action="{{.Action}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<fieldset>
<legend>{{if .Multi}}Your vote: choose one or more{{else}}Your vote: choose one{{end}}</legend>
{{range .Options}}<p><label><input type="{{if $.Multi}}checkbox{{else}}radio{{end}}" name="option" value="{{.ID}}"{{if .Mine}} checked{{end}}{{if not $.Multi}} required{{end}}> {{.Label}}</label></p>
{{end}}</fieldset>
<p class="meta">{{if .Anonymous}}Votes are anonymous.{{else}}This poll is not anonymous: everyone will see your choice.{{end}}</p>
<p><button type="submit">{{if .Voted}}Change your vote{{else}}Vote{{end}}</button></p>
</form>
{{- else if .Closed}}
<p>This poll is closed.</p>
{{- else}}
<p>You cannot vote in polls.</p>
{{- end}}
{{if .Results}}{{.ResultsHeading}}
<p>{{.Total}} vote(s) from {{.Voters}} member(s).</p>
<ul class="results">{{range .Options}}<li>{{.Text}}<br><meter min="0" max="100" value="{{.Percent}}" aria-hidden="true"></meter>{{if .Names}}<br><span class="meta">Voted: {{.Names}}</span>{{end}}</li>
{{end}}</ul>
{{- else}}
<p class="meta">Results are shown after you vote or when the poll closes.</p>
{{- end}}
</section>{{end}}
`))

func execTmpl(name string, data any) (template.HTML, error) {
	var b bytes.Buffer
	if err := webTmpl.ExecuteTemplate(&b, name, data); err != nil {
		return "", err
	}
	return template.HTML(b.String()), nil //nolint:gosec // html/template output
}

// heading returns <hN id=...>text</hN>, escaped. level is clamped to 2-6.
func heading(level int, id, text string) template.HTML {
	level = min(max(level, 2), 6)
	return template.HTML(fmt.Sprintf(`<h%d id="%s">%s</h%d>`, level, //nolint:gosec // both escaped
		template.HTMLEscapeString(id), template.HTMLEscapeString(text), level))
}

// WebPanel renders poll id for viewer: its details, a vote form posting to
// action (if the poll is open and the viewer may vote), and the results if
// CanSeeResults allows. The question is a heading at level (2-6), with the
// results heading one below; level 0 leaves the question out, for a page
// whose own title is the question. The caller must already have checked
// that the viewer may see the poll's context (e.g. the conference thread).
func (p *Plugin) WebPanel(ctx context.Context, viewer, id int64, level int, action, csrf string) (template.HTML, error) {
	pl, err := p.Get(ctx, viewer, id)
	if err != nil {
		return "", err
	}
	set, err := p.h.Perms.Permissions(ctx, viewer)
	if err != nil {
		return "", err
	}
	closed := pl.Closed(p.now())
	type optOut struct {
		ID          int64
		Label, Text string
		Names       string
		Percent     int
		Mine        bool
	}
	total := 0
	for _, o := range pl.Options {
		total += o.Votes
	}
	var opts []optOut
	for i, o := range pl.Options {
		pct := 0
		if total > 0 {
			pct = o.Votes * 100 / total
		}
		mine := slices.Contains(pl.MyVotes, o.ID)
		text := fmt.Sprintf("Option %d, %s: %d vote(s), %d percent", i+1, o.Label, o.Votes, pct)
		if mine {
			text += " (your vote)"
		}
		out := optOut{ID: o.ID, Label: o.Label, Text: text + ".", Percent: pct, Mine: mine}
		if !pl.Anonymous {
			out.Names = strings.Join(o.Voters, ", ")
		}
		opts = append(opts, out)
	}
	data := map[string]any{
		"ID": pl.ID, "About": about(pl, closed), "Multi": pl.Multi, "Anonymous": pl.Anonymous,
		"Closed": closed, "CanVote": !closed && set.Has(PermVote), "Voted": len(pl.MyVotes) > 0,
		"Action": action, "CSRF": csrf, "Options": opts,
		"Results": p.CanSeeResults(pl, viewer, set), "Total": total, "Voters": pl.Voters,
	}
	resultsLevel := 2
	if level > 0 {
		data["Heading"] = heading(level, "poll-"+strconv.FormatInt(pl.ID, 10)+"-q", pl.Question)
		resultsLevel = level + 1
	}
	data["ResultsHeading"] = heading(resultsLevel, "poll-"+strconv.FormatInt(pl.ID, 10)+"-results", "Results")
	return execTmpl("panel", data)
}

// about describes a poll's rules and state in one line, for the SSH menu
// and the web.
func about(pl Poll, closed bool) string {
	var parts []string
	if pl.Multi {
		parts = append(parts, "You may choose more than one option.")
	}
	if pl.Anonymous {
		parts = append(parts, "Votes are anonymous.")
	} else {
		parts = append(parts, "Votes are not anonymous: everyone can see who voted for what.")
	}
	switch {
	case closed:
		parts = append(parts, "This poll is closed.")
	case pl.ClosesAt != nil:
		parts = append(parts, "Closes "+pl.ClosesAt.UTC().Format("2006-01-02 15:04 UTC")+".")
	}
	if len(pl.MyVotes) > 0 {
		parts = append(parts, "You have voted.")
	}
	parts = append(parts, "Created by "+pl.Creator+".")
	return strings.Join(parts, " ")
}

// WebVote records the vote posted from a WebPanel form (fields "option").
// Expected problems come back as a *plugin.WebError for the member. As
// with WebPanel, the caller checks access to the poll's context.
func (p *Plugin) WebVote(r *http.Request, viewer, id int64) error {
	if err := r.ParseForm(); err != nil {
		return &plugin.WebError{Status: http.StatusBadRequest, Message: "The vote could not be read."}
	}
	var options []int64
	for _, v := range r.PostForm["option"] {
		o, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return &plugin.WebError{Status: http.StatusBadRequest, Message: "Invalid vote: unknown option."}
		}
		options = append(options, o)
	}
	err := p.Vote(r.Context(), viewer, id, options)
	switch {
	case errors.Is(err, ErrNotFound):
		return plugin.ErrWebNotFound
	case errors.Is(err, perm.ErrForbidden):
		return &plugin.WebError{Status: http.StatusForbidden, Message: "You cannot vote in polls."}
	case errors.Is(err, ErrClosed), errors.Is(err, ErrBadVote):
		return &plugin.WebError{Status: http.StatusBadRequest, Message: message(err)}
	}
	return err
}

func (p *Plugin) webRoutes() []plugin.WebRoute {
	return []plugin.WebRoute{
		{Path: "/", Handle: p.webList(true)},
		{Path: "/closed", Handle: p.webList(false)},
		{Path: "/{id}", Handle: p.webPoll},
		{Path: "/{id}/vote", Method: http.MethodPost, AnyOf: []string{PermVote}, Handle: p.webVote},
	}
}

// webList lists open or closed polls from the Polls menu.
func (p *Plugin) webList(open bool) func(*http.Request, plugin.WebSession) (plugin.WebPage, error) {
	return func(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
		list, err := p.List(r.Context(), open)
		if err != nil {
			return plugin.WebPage{}, err
		}
		type pollOut struct {
			Question, Href string
			Pinned         bool
		}
		var out []pollOut
		for _, pl := range list {
			out = append(out, pollOut{pl.Question, s.Path("/" + strconv.FormatInt(pl.ID, 10)), pl.Pinned})
		}
		data := map[string]any{"Polls": out, "Empty": "There are no open polls.", "Other": s.Path("/closed"), "OtherLabel": "Closed polls and results"}
		title := "Polls"
		if !open {
			data["Empty"], data["Other"], data["OtherLabel"] = "There are no closed polls.", s.Path("/"), "Open polls"
			title = "Closed polls"
		}
		body, err := execTmpl("list", data)
		return plugin.WebPage{Title: title, Body: body}, err
	}
}

// menuPoll returns a Polls-menu poll. Polls attached elsewhere (a
// conference post) are only shown where they belong, which checks access.
func (p *Plugin) menuPoll(r *http.Request, viewer int64) (Poll, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return Poll{}, plugin.ErrWebNotFound
	}
	pl, err := p.Get(r.Context(), viewer, id)
	if errors.Is(err, ErrNotFound) || (err == nil && pl.Context != "") {
		return Poll{}, plugin.ErrWebNotFound
	}
	return pl, err
}

func (p *Plugin) webPoll(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	pl, err := p.menuPoll(r, s.UserID())
	if err != nil {
		return plugin.WebPage{}, err
	}
	panel, err := p.WebPanel(r.Context(), s.UserID(), pl.ID, 0, s.Path("/"+strconv.FormatInt(pl.ID, 10)+"/vote"), s.CSRF())
	if err != nil {
		return plugin.WebPage{}, err
	}
	back := template.HTML(`<p><a href="` + template.HTMLEscapeString(s.Path("/")) + `">All polls</a></p>`) //nolint:gosec // escaped
	return plugin.WebPage{Title: pl.Question, Body: panel + back}, nil
}

func (p *Plugin) webVote(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	pl, err := p.menuPoll(r, s.UserID())
	if err != nil {
		return plugin.WebPage{}, err
	}
	if err := p.WebVote(r, s.UserID(), pl.ID); err != nil {
		return plugin.WebPage{}, err
	}
	return plugin.WebPage{Redirect: s.Path("/" + strconv.FormatInt(pl.ID, 10))}, nil
}
