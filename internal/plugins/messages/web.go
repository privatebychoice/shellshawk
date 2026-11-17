package messages

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
)

// The web side has the three folders, reading, writing and replying, and
// deleting and restoring, with the same rules as over SSH. Actions that
// cannot be undone (removing from Sent, deleting permanently, emptying the
// Deleted folder) need a ticked confirmation box.

var webTmpl = template.Must(template.New("msg").Parse(`
{{define "notice"}}{{if .}}<p class="notice" role="status">{{.}}</p>{{end}}{{end}}

{{define "folders"}}<nav aria-label="Folders" class="folders"><ul>
{{range .}}<li><a href="{{.Href}}"{{if .Current}} aria-current="page"{{end}}>{{.Label}}</a></li>
{{end}}</ul></nav>{{end}}

{{define "confirm"}}<form method="post" action="{{.Action}}" class="form">
<input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .Folder}}<input type="hidden" name="folder" value="{{.Folder}}">{{end}}
<p><label><input type="checkbox" name="confirm" value="yes" required> {{.Check}}</label></p>
<p><button type="submit">{{.Button}}</button></p>
</form>{{end}}

{{define "folder"}}{{template "notice" .Notice}}{{template "folders" .Folders}}
{{if .Write}}<p><a href="{{.Write}}">Write a message</a></p>{{end}}
{{if .Intro}}<p>{{.Intro}}</p>{{end}}
{{if .Messages}}<ul class="list">{{range .Messages}}<li{{if not .Read}} class="unread"{{end}}>{{if not .Read}}New: {{end}}<a href="{{.Href}}">{{.Subject}}</a>
<span class="meta">{{.Who}}, {{.Date}}</span></li>
{{end}}</ul>{{else}}<p>{{.Empty}}</p>{{end}}
{{if .EmptyForm}}<section aria-labelledby="empty-heading"><h2 id="empty-heading">Empty the Deleted folder</h2>
{{template "confirm" .EmptyForm}}</section>{{end}}{{end}}

{{define "message"}}{{template "folders" .Folders}}
<dl class="meta"><dt>From</dt><dd>{{.From}}</dd><dt>To</dt><dd>{{.To}}</dd><dt>Date</dt><dd>{{.Date}}</dd></dl>
<article class="post">{{.Body}}</article>
<section aria-labelledby="actions-heading"><h2 id="actions-heading">Actions</h2>
{{if .Reply}}<p><a href="{{.Reply}}">Reply</a></p>{{end}}
{{if .Delete}}<form method="post" action="{{.Delete}}" class="form">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<p><button type="submit">Delete</button> <span class="meta">It moves to Deleted, where you can restore it for {{.Days}} days.</span></p>
</form>{{end}}
{{if .Restore}}<form method="post" action="{{.Restore}}" class="form">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<p><button type="submit">Move back to the inbox</button></p>
</form>{{end}}
{{if .Confirm}}{{template "confirm" .Confirm}}{{end}}
</section>
<p><a href="{{.Back}}">Back to {{.BackLabel}}</a></p>{{end}}

{{define "compose"}}{{if .Error}}<p class="error" id="compose-error" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}" class="form compose">
<input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .Parent}}<input type="hidden" name="parent" value="{{.Parent}}">{{end}}
<p><label for="msg-to">To</label>
<input type="text" id="msg-to" name="to" maxlength="1000" autocomplete="off" autocapitalize="none" spellcheck="false" value="{{.Values.to}}" aria-describedby="msg-to-help{{if .Errors.to}} msg-to-error{{end}}"{{if .Errors.to}} aria-invalid="true"{{end}}>
<span class="meta" id="msg-to-help">Usernames, separated by commas.</span></p>
{{if .Errors.to}}<p class="error" id="msg-to-error">{{.Errors.to}}</p>{{end}}
{{if .Groups}}<fieldset><legend>Also send to these contact groups</legend>
{{range .Groups}}<p><label><input type="checkbox" name="groups" value="{{.Name}}"{{if .Checked}} checked{{end}}> {{.Name}} ({{.Members}})</label></p>
{{end}}</fieldset>{{end}}
<p><label for="msg-subject">Subject</label>
<input type="text" id="msg-subject" name="subject" maxlength="{{.MaxSubject}}" required value="{{.Values.subject}}"{{if .Errors.subject}} aria-invalid="true" aria-describedby="msg-subject-error"{{end}}></p>
{{if .Errors.subject}}<p class="error" id="msg-subject-error">{{.Errors.subject}}</p>{{end}}
<p><label for="msg-body">Message</label>
<textarea id="msg-body" name="body" rows="12" maxlength="{{.MaxBody}}" required aria-describedby="msg-body-help{{if .Errors.body}} msg-body-error{{end}}"{{if .Errors.body}} aria-invalid="true"{{end}}>{{.Values.body}}</textarea>
<span class="meta" id="msg-body-help">Markdown: **bold**, *italic*, links and lists. At most {{.MaxBody}} characters.</span></p>
{{if .Errors.body}}<p class="error" id="msg-body-error">{{.Errors.body}}</p>{{end}}
<p><button type="submit">Send</button></p>
</form>
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
	send := []string{PermSend}
	return []plugin.WebRoute{
		{Path: "/", Nav: "Messages", Handle: p.webFolder(Inbox)},
		{Path: "/sent", Handle: p.webFolder(Sent)},
		{Path: "/deleted", Handle: p.webFolder(Deleted)},
		{Path: "/deleted/empty", Method: http.MethodPost, Handle: p.webEmpty},
		{Path: "/m/{id}", Handle: p.webMessage},
		{Path: "/m/{id}/delete", Method: http.MethodPost, Handle: p.webAction("delete")},
		{Path: "/m/{id}/restore", Method: http.MethodPost, Handle: p.webAction("restore")},
		{Path: "/m/{id}/forever", Method: http.MethodPost, Handle: p.webAction("forever")},
		{Path: "/new", AnyOf: send, Handle: p.webCompose},
		{Path: "/new", Method: http.MethodPost, AnyOf: send, Handle: p.webSend},
	}
}

// folderPaths are each folder's page, relative to the plugin.
var folderPaths = map[string]string{Inbox: "/", Sent: "/sent", Deleted: "/deleted"}

// notices are confirmations after a redirect (?done=...): fixed text only.
var notices = map[string]string{
	"sent":     "Message sent.",
	"deleted":  "Message moved to Deleted.",
	"removed":  "Message removed from Sent.",
	"restored": "Message moved back to the inbox.",
	"forever":  "Message deleted permanently.",
	"emptied":  "The Deleted folder is empty.",
}

type folderLink struct {
	Label, Href string
	Current     bool
}

func (p *Plugin) folderLinks(r *http.Request, s plugin.WebSession, current string) ([]folderLink, Counts, error) {
	c, err := p.Count(r.Context(), s.UserID())
	if err != nil {
		return nil, Counts{}, err
	}
	return []folderLink{
		{fmt.Sprintf("Inbox (%d unread)", c.Unread), s.Path("/"), current == Inbox},
		{"Sent", s.Path("/sent"), current == Sent},
		{fmt.Sprintf("Deleted (%d)", c.Deleted), s.Path("/deleted"), current == Deleted},
	}, c, nil
}

// webFolder lists one folder.
func (p *Plugin) webFolder(folder string) func(*http.Request, plugin.WebSession) (plugin.WebPage, error) {
	titles := map[string]string{Inbox: "Messages", Sent: "Sent messages", Deleted: "Deleted messages"}
	empty := map[string]string{Inbox: "Your inbox is empty.", Sent: "You have no sent messages.", Deleted: "There are no deleted messages."}
	return func(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
		ctx := r.Context()
		links, c, err := p.folderLinks(r, s, folder)
		if err != nil {
			return plugin.WebPage{}, err
		}
		list, err := p.List(ctx, s.UserID(), folder)
		if err != nil {
			return plugin.WebPage{}, err
		}
		type item struct {
			Subject, Who, Date, Href string
			Read                     bool
		}
		var items []item
		for _, m := range list {
			who := "from " + m.From
			if folder == Sent {
				who = "to " + strings.Join(m.To, ", ")
			}
			href := s.Path("/m/" + strconv.FormatInt(m.ID, 10))
			if folder != Inbox {
				href += "?folder=" + folder
			}
			items = append(items, item{m.Subject, who, fmtTime(m), href, m.Read || folder == Sent})
		}
		data := map[string]any{
			"Notice": notices[r.URL.Query().Get("done")], "Folders": links, "Messages": items, "Empty": empty[folder],
		}
		switch folder {
		case Inbox:
			data["Intro"] = fmt.Sprintf("%d unread, %d read.", c.Unread, c.Read)
		case Deleted:
			data["Intro"] = fmt.Sprintf("Messages here are removed permanently after %d days. You can move them back to the inbox until then.", p.DeletedDays(ctx))
			if len(items) > 0 {
				data["EmptyForm"] = map[string]any{"Action": s.Path("/deleted/empty"), "CSRF": s.CSRF(),
					"Check": fmt.Sprintf("Yes, delete all %d message(s) here permanently. This cannot be undone.", len(items)), "Button": "Empty the Deleted folder"}
			}
		}
		if set, err := s.Permissions(ctx); err != nil {
			return plugin.WebPage{}, err
		} else if set.Has(PermSend) {
			data["Write"] = s.Path("/new")
		}
		body, err := execTmpl("folder", data)
		return plugin.WebPage{Title: titles[folder], Body: body}, err
	}
}

// messageFolder is the folder a message was opened from (?folder=), which
// decides what Delete does: a message sent to oneself is in both Inbox and
// Sent. Without one, it is where the member's copy is. A wrong folder only
// offers an action that then fails as not found.
func messageFolder(r *http.Request, m Message) string {
	switch r.URL.Query().Get("folder") {
	case Sent:
		return Sent
	case Deleted:
		if m.Deleted {
			return Deleted
		}
	}
	switch {
	case m.Role == RoleSender:
		return Sent
	case m.Deleted:
		return Deleted
	}
	return Inbox
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return 0, plugin.ErrWebNotFound
	}
	return id, nil
}

// webMessage shows a message the member sent or received, with what can be
// done with it. Opening a received message marks it read, as in the BBS.
func (p *Plugin) webMessage(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	ctx := r.Context()
	id, err := pathID(r)
	if err != nil {
		return plugin.WebPage{}, err
	}
	m, err := p.Read(ctx, s.UserID(), id)
	if errors.Is(err, ErrNotFound) {
		return plugin.WebPage{}, plugin.ErrWebNotFound
	}
	if err != nil {
		return plugin.WebPage{}, err
	}
	folder := messageFolder(r, m)
	links, _, err := p.folderLinks(r, s, folder)
	if err != nil {
		return plugin.WebPage{}, err
	}
	set, err := s.Permissions(ctx)
	if err != nil {
		return plugin.WebPage{}, err
	}
	base := "/m/" + strconv.FormatInt(m.ID, 10)
	backLabel := map[string]string{Inbox: "the inbox", Sent: "Sent", Deleted: "Deleted"}[folder]
	data := map[string]any{
		"Folders": links, "From": m.From, "To": strings.Join(m.To, ", "), "Date": fmtTime(m.Summary),
		"Body": s.Markdown(m.Body), "CSRF": s.CSRF(), "Days": p.DeletedDays(ctx),
		"Back": s.Path(folderPaths[folder]), "BackLabel": backLabel,
	}
	if set.Has(PermSend) && m.SenderID != 0 && m.Role == RoleRecipient {
		data["Reply"] = s.Path("/new?reply=" + strconv.FormatInt(m.ID, 10))
	}
	switch folder {
	case Inbox:
		data["Delete"] = s.Path(base + "/delete")
	case Sent:
		data["Confirm"] = map[string]any{"Action": s.Path(base + "/delete"), "Folder": Sent, "CSRF": s.CSRF(),
			"Check": "Yes, remove it from Sent. It cannot be restored; recipients keep their copies.", "Button": "Remove from Sent"}
	case Deleted:
		data["Restore"] = s.Path(base + "/restore")
		data["Confirm"] = map[string]any{"Action": s.Path(base + "/forever"), "CSRF": s.CSRF(),
			"Check": "Yes, delete it permanently. This cannot be undone.", "Button": "Delete permanently"}
	}
	body, err := execTmpl("message", data)
	return plugin.WebPage{Title: m.Subject, Body: body}, err
}

// confirmed refuses an irreversible action whose box was not ticked.
func confirmed(r *http.Request) error {
	if r.PostFormValue("confirm") != "yes" {
		return &plugin.WebError{Status: http.StatusBadRequest, Message: "Tick the box to confirm, then try again."}
	}
	return nil
}

// webAction deletes, restores or permanently deletes a message, then goes
// back to the folder it was in.
func (p *Plugin) webAction(action string) func(*http.Request, plugin.WebSession) (plugin.WebPage, error) {
	return func(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
		ctx := r.Context()
		id, err := pathID(r)
		if err != nil {
			return plugin.WebPage{}, err
		}
		var back, done string
		switch action {
		case "delete":
			if r.PostFormValue("folder") == Sent {
				if err := confirmed(r); err != nil {
					return plugin.WebPage{}, err
				}
				err, back, done = p.Delete(ctx, s.UserID(), id, Sent), "/sent", "removed"
			} else {
				err, back, done = p.Delete(ctx, s.UserID(), id, Inbox), "/", "deleted"
			}
		case "restore":
			err, back, done = p.Restore(ctx, s.UserID(), id), "/deleted", "restored"
		case "forever":
			if err := confirmed(r); err != nil {
				return plugin.WebPage{}, err
			}
			err, back, done = p.DeleteForever(ctx, s.UserID(), id), "/deleted", "forever"
		}
		if errors.Is(err, ErrNotFound) {
			return plugin.WebPage{}, plugin.ErrWebNotFound
		}
		if err != nil {
			return plugin.WebPage{}, err
		}
		return plugin.WebPage{Redirect: s.Path(back + "?done=" + done)}, nil
	}
}

// webEmpty empties the Deleted folder.
func (p *Plugin) webEmpty(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	if err := confirmed(r); err != nil {
		return plugin.WebPage{}, err
	}
	if _, err := p.EmptyDeleted(r.Context(), s.UserID()); err != nil {
		return plugin.WebPage{}, err
	}
	return plugin.WebPage{Redirect: s.Path("/deleted?done=emptied")}, nil
}

// webCompose shows the form for a new message, or a reply (?reply=id) or a
// message to someone (?to=username).
func (p *Plugin) webCompose(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	d := Draft{To: r.URL.Query().Get("to")}
	if v := r.URL.Query().Get("reply"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return plugin.WebPage{}, plugin.ErrWebNotFound
		}
		m, err := p.Read(r.Context(), s.UserID(), id)
		if errors.Is(err, ErrNotFound) || (err == nil && (m.Role != RoleRecipient || m.SenderID == 0)) {
			return plugin.WebPage{}, plugin.ErrWebNotFound
		}
		if err != nil {
			return plugin.WebPage{}, err
		}
		d = replyDraft(m)
	}
	return p.composePage(r, s, d, "", nil)
}

// composePage renders the message form with d filled in. general and
// errs ("to", "subject", "body") show why a message was not sent.
func (p *Plugin) composePage(r *http.Request, s plugin.WebSession, d Draft, general string, errs map[string]string) (plugin.WebPage, error) {
	groups, err := p.contacts.Groups(r.Context(), s.UserID())
	if err != nil {
		return plugin.WebPage{}, err
	}
	type groupOut struct {
		Name    string
		Members int
		Checked bool
	}
	var gs []groupOut
	for _, g := range groups {
		checked := false
		for _, c := range d.ContactGroups {
			checked = checked || c == g.Name
		}
		gs = append(gs, groupOut{g.Name, g.Members, checked})
	}
	parent := ""
	if d.ParentID != 0 {
		parent = strconv.FormatInt(d.ParentID, 10)
	}
	title := "Write a message"
	if d.ParentID != 0 {
		title = "Reply"
	}
	body, err := execTmpl("compose", map[string]any{
		"Action": s.Path("/new"), "CSRF": s.CSRF(), "Parent": parent, "Groups": gs, "Error": general, "Errors": errs,
		"Values":     map[string]string{"to": d.To, "subject": d.Subject, "body": d.Body},
		"MaxSubject": MaxSubject, "MaxBody": p.MaxBody(r.Context()), "Back": s.Path("/"),
	})
	return plugin.WebPage{Title: title, Body: body}, err
}

// sentence turns an error into a sentence for the member.
func sentence(err error) string {
	msg := strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
	if msg == "" {
		return ""
	}
	return strings.ToUpper(msg[:1]) + msg[1:] + "."
}

// webSend sends the message form; a refused message comes back with its
// errors and everything typed.
func (p *Plugin) webSend(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	d := Draft{To: r.PostFormValue("to"), Subject: r.PostFormValue("subject"), Body: r.PostFormValue("body")}
	for _, g := range r.PostForm["groups"] {
		if g != "" {
			d.ContactGroups = append(d.ContactGroups, g)
		}
	}
	if v := r.PostFormValue("parent"); v != "" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return plugin.WebPage{}, &plugin.WebError{Status: http.StatusBadRequest, Message: "The message could not be read."}
		}
		d.ParentID = id
	}
	// The browser sends line breaks as CRLF; store them as the BBS does.
	d.Body = strings.ReplaceAll(d.Body, "\r\n", "\n")
	if strings.TrimSpace(d.To) == "" && len(d.ContactGroups) == 0 {
		return p.composePage(r, s, d, "", map[string]string{"to": sentence(ErrNoneToSend)})
	}
	_, err := p.Send(r.Context(), s.UserID(), d)
	var re *RecipientError
	switch {
	case err == nil:
		p.h.Log.Info("message sent from the web", "user_id", s.UserID())
		return plugin.WebPage{Redirect: s.Path("/sent?done=sent")}, nil
	case errors.As(err, &re), errors.Is(err, ErrNoneToSend):
		return p.composePage(r, s, d, "", map[string]string{"to": sentence(err)})
	case errors.Is(err, ErrNotFound):
		// The message being replied to is gone (or never was the member's).
		d.ParentID = 0
		return p.composePage(r, s, d, "The message you are replying to no longer exists. You can still send this as a new message.", nil)
	case errors.Is(err, ErrInvalid):
		field := "body"
		switch {
		case strings.Contains(err.Error(), "subject"):
			field = "subject"
		case strings.Contains(err.Error(), "recipients"):
			field = "to"
		}
		return p.composePage(r, s, d, "", map[string]string{field: sentence(err)})
	case errors.Is(err, ErrRateLimit):
		return p.composePage(r, s, d, sentence(err), nil)
	case errors.Is(err, perm.ErrForbidden):
		return plugin.WebPage{}, &plugin.WebError{Status: http.StatusForbidden, Message: "You do not have permission to send messages."}
	}
	return plugin.WebPage{}, err
}
