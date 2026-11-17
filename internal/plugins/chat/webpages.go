package chat

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
)

// Web pages: the channel list, search, a page per channel with the live
// panel, and private chats (start one; invite, change the topic, remove
// someone, close it). Slash commands and channel management stay on SSH.

var pagesTmpl = template.Must(template.New("pages").Parse(`
{{define "notice"}}{{if .}}<p class="notice" role="status">{{.}}</p>{{end}}{{end}}

{{define "list"}}{{template "notice" .Notice}}
<form method="get" action="{{.FindAction}}" role="search" class="form">
<p><label for="chat-find">Find a channel by name or topic</label>
<input type="search" id="chat-find" name="q" value="{{.Query}}" maxlength="{{.MaxQuery}}" required>
<button type="submit">Find</button></p>
</form>
{{if .Start}}<p><a href="{{.Start}}">Start a private chat</a></p>{{end}}
{{range .Groups}}<section aria-labelledby="{{.ID}}">
<h2 id="{{.ID}}">{{.Heading}}</h2>
<ul class="list">{{range .Channels}}<li><a href="{{.Href}}">#{{.Name}}</a> <span class="meta">{{.Here}}{{if .Topic}} · {{.Topic}}{{end}}</span></li>
{{end}}</ul>
</section>
{{end}}{{if .None}}<p>{{.None}}</p>{{end}}
{{if .Back}}<p><a href="{{.Back}}">All chats</a></p>{{end}}{{end}}

{{define "channel"}}{{template "notice" .Notice}}
{{.Panel}}
{{if .Private}}<section aria-labelledby="private-heading">
<h2 id="private-heading">Private chat</h2>
<p>Started by {{.Creator}}. Invited: {{if .Invited}}{{.InvitedList}}{{else}}nobody yet{{end}}.</p>
<form method="post" action="{{.Actions.invite}}" class="form">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<p><label for="invite-name">Invite a member (username)</label>
<input type="text" id="invite-name" name="username" maxlength="32" required autocomplete="off" autocapitalize="none" spellcheck="false" value="{{.Values.invite}}"{{if .Errors.invite}} aria-invalid="true" aria-describedby="invite-error"{{end}}></p>
{{if .Errors.invite}}<p class="error" id="invite-error" role="alert">{{.Errors.invite}}</p>{{end}}
<p><button type="submit">Invite</button></p>
</form>
{{if .Manage}}
<form method="post" action="{{.Actions.topic}}" class="form">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<p><label for="topic">Topic (leave empty to remove it)</label>
<input type="text" id="topic" name="topic" maxlength="{{.MaxTopic}}" value="{{.Values.topic}}"{{if .Errors.topic}} aria-invalid="true" aria-describedby="topic-error"{{end}}></p>
{{if .Errors.topic}}<p class="error" id="topic-error" role="alert">{{.Errors.topic}}</p>{{end}}
<p><button type="submit">Change the topic</button></p>
</form>
{{if .Removable}}<form method="post" action="{{.Actions.remove}}" class="form">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<p><label for="remove-name">Remove a member</label>
<select id="remove-name" name="username" required{{if .Errors.remove}} aria-invalid="true" aria-describedby="remove-error"{{end}}>
{{range .Removable}}<option value="{{.}}">{{.}}</option>
{{end}}</select></p>
{{if .Errors.remove}}<p class="error" id="remove-error" role="alert">{{.Errors.remove}}</p>{{end}}
<p><button type="submit">Remove</button></p>
</form>{{end}}
<form method="post" action="{{.Actions.close}}" class="form">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<p><label><input type="checkbox" name="confirm" value="yes" required{{if .Errors.close}} aria-invalid="true" aria-describedby="close-error"{{end}}> Yes, close this chat for everyone and delete its log</label></p>
{{if .Errors.close}}<p class="error" id="close-error" role="alert">{{.Errors.close}}</p>{{end}}
<p><button type="submit">Close this chat</button></p>
</form>
{{end}}</section>
{{end}}<p><a href="{{.Back}}">All chats</a></p>{{end}}

{{define "new"}}{{if .Error}}<p class="error" id="new-error" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}" class="form"{{if .Error}} aria-describedby="new-error"{{end}}>
<input type="hidden" name="csrf" value="{{.CSRF}}">
<p><label for="new-name">Name</label>
<input type="text" id="new-name" name="name" maxlength="32" required autocomplete="off" autocapitalize="none" spellcheck="false" aria-describedby="new-name-help" value="{{.Values.name}}">
<span class="meta" id="new-name-help">2 to 32 lowercase letters, digits and '-', starting with a letter.</span></p>
<p><label for="new-invite">Invite (usernames, separated by commas)</label>
<input type="text" id="new-invite" name="invite" maxlength="1000" autocomplete="off" autocapitalize="none" spellcheck="false" aria-describedby="new-invite-help" value="{{.Values.invite}}">
<span class="meta" id="new-invite-help">Only the people you invite can join. You can invite more later.</span></p>
<p><label for="new-topic">Topic</label>
<input type="text" id="new-topic" name="topic" maxlength="{{.MaxTopic}}" value="{{.Values.topic}}"></p>
<p><button type="submit">Start the chat</button></p>
</form>
<p><a href="{{.Back}}">All chats</a></p>{{end}}
`))

func execPage(name string, data any) (template.HTML, error) {
	var b bytes.Buffer
	if err := pagesTmpl.ExecuteTemplate(&b, name, data); err != nil {
		return "", err
	}
	return template.HTML(b.String()), nil //nolint:gosec // html/template output
}

// notices are the confirmations shown after an action (?done=...). Only
// fixed text: nothing a member typed goes into a URL.
var notices = map[string]string{
	"invite": "Invitation sent: they can now join from their chat list.",
	"topic":  "Topic changed.",
	"remove": "Removed from this chat.",
	"closed": "The chat was closed.",
}

// webMessage is the text shown for an expected error, or "" if err is not
// one.
func webMessage(err error) string {
	switch {
	case errors.Is(err, perm.ErrForbidden):
		return "You do not have permission to do that."
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrExists):
		return sentence(err)
	}
	return ""
}

type chanLink struct {
	Name, Href, Here, Topic string
}

type chanGroup struct {
	ID, Heading string
	Channels    []chanLink
}

// groupChannels sorts channels into the list's sections.
func (p *Plugin) groupChannels(s plugin.WebSession, chans []Channel) []chanGroup {
	groups := []chanGroup{
		{ID: "channels", Heading: "Channels"},
		{ID: "private", Heading: "Private chats"},
		{ID: "threads", Heading: "Conference thread chats"},
	}
	for _, c := range chans {
		i := 0
		switch c.Kind {
		case KindAdHoc:
			i = 1
		case KindThread:
			i = 2
		}
		here := "nobody here"
		if n := p.hub.count(c.ID); n > 0 {
			here = strconv.Itoa(n) + " here"
		}
		groups[i].Channels = append(groups[i].Channels, chanLink{c.Name, s.Path("/c/" + strconv.FormatInt(c.ID, 10)), here, c.Topic})
	}
	out := groups[:0]
	for _, g := range groups {
		if len(g.Channels) > 0 {
			out = append(out, g)
		}
	}
	return out
}

func (p *Plugin) listData(r *http.Request, s plugin.WebSession) (map[string]any, error) {
	set, err := s.Permissions(r.Context())
	if err != nil {
		return nil, err
	}
	data := map[string]any{"FindAction": s.Path("/find"), "MaxQuery": MaxTopic}
	if set.Has(PermCreate) {
		data["Start"] = s.Path("/new")
	}
	return data, nil
}

// webList is the Chat page: every channel the member may join.
func (p *Plugin) webList(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	chans, err := p.Accessible(r.Context(), s.UserID())
	if err != nil {
		return plugin.WebPage{}, err
	}
	data, err := p.listData(r, s)
	if err != nil {
		return plugin.WebPage{}, err
	}
	data["Notice"] = notices[r.URL.Query().Get("done")]
	data["Groups"] = p.groupChannels(s, chans)
	if len(chans) == 0 {
		data["None"] = "There are no channels you can join."
	}
	body, err := execPage("list", data)
	return plugin.WebPage{Title: "Chat", Body: body}, err
}

// webFind searches the channels the member may join.
func (p *Plugin) webFind(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	data, err := p.listData(r, s)
	if err != nil {
		return plugin.WebPage{}, err
	}
	data["Query"], data["Back"] = q, s.Path("/")
	found, err := p.FindAccessible(r.Context(), s.UserID(), q)
	switch {
	case errors.Is(err, ErrInvalid):
		data["None"] = sentence(err)
	case err != nil:
		return plugin.WebPage{}, err
	case len(found) == 0:
		data["None"] = "No channel you can join matches “" + q + "”."
	default:
		data["Groups"] = p.groupChannels(s, found)
	}
	body, err := execPage("list", data)
	return plugin.WebPage{Title: "Find a channel", Body: body}, err
}

// channelPage renders a channel's page. errs and vals re-show a private
// chat form that was refused ("invite", "topic", "remove", "close").
func (p *Plugin) channelPage(r *http.Request, s plugin.WebSession, c Channel, notice string, errs, vals map[string]string) (plugin.WebPage, error) {
	ctx := r.Context()
	base := "/c/" + strconv.FormatInt(c.ID, 10)
	panel, err := p.WebPanel(ctx, s.UserID(), c.ID, "Messages", s.CSRF(), s.Path(base))
	if err != nil {
		return plugin.WebPage{}, err
	}
	data := map[string]any{
		"Notice": notice, "Panel": panel, "Back": s.Path("/"), "CSRF": s.CSRF(), "MaxTopic": MaxTopic,
		"Errors": errs, "Values": vals, "Private": c.Kind == KindAdHoc,
		"Actions": map[string]string{
			"invite": s.Path(base + "/invite"), "topic": s.Path(base + "/topic"),
			"remove": s.Path(base + "/remove"), "close": s.Path(base + "/close"),
		},
	}
	if c.Kind == KindAdHoc {
		invited, err := p.Invited(ctx, c)
		if err != nil {
			return plugin.WebPage{}, err
		}
		names, err := p.h.Auth.Usernames(ctx, []int64{c.CreatorID})
		if err != nil {
			return plugin.WebPage{}, err
		}
		creator := names[c.CreatorID]
		if creator == "" {
			creator = "a former member"
		}
		var list, removable []string
		for _, i := range invited {
			list = append(list, i.Name)
			if i.ID != s.UserID() {
				removable = append(removable, i.Name)
			}
		}
		manage, err := p.canModerate(ctx, s.UserID(), c)
		if err != nil {
			return plugin.WebPage{}, err
		}
		if _, ok := vals["topic"]; !ok {
			if vals == nil {
				vals = map[string]string{}
			}
			vals["topic"] = c.Topic
			data["Values"] = vals
		}
		data["Creator"], data["Invited"], data["InvitedList"] = creator, len(list) > 0, strings.Join(list, ", ")
		data["Manage"], data["Removable"] = manage, removable
	}
	body, err := execPage("channel", data)
	return plugin.WebPage{Title: "#" + c.Name, Body: body}, err
}

// webChannelPage shows one channel: the live panel and, in a private
// chat, its forms.
func (p *Plugin) webChannelPage(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	c, _, err := p.webChannel(r, s)
	if err != nil {
		return plugin.WebPage{}, err
	}
	return p.channelPage(r, s, c, notices[r.URL.Query().Get("done")], nil, nil)
}

// privateAction runs a private chat form. do returns an error for the
// member (shown with the form) or an unexpected one.
func (p *Plugin) privateAction(form, done string, do func(r *http.Request, c Channel, u auth.User) error) func(*http.Request, plugin.WebSession) (plugin.WebPage, error) {
	return func(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
		c, u, err := p.webChannel(r, s)
		if err != nil {
			return plugin.WebPage{}, err
		}
		if c.Kind != KindAdHoc {
			return plugin.WebPage{}, plugin.ErrWebNotFound
		}
		err = do(r, c, u)
		if errors.Is(err, perm.ErrForbidden) {
			// Only reachable by a hand-made request: the page shows these
			// forms only to people allowed to use them.
			return plugin.WebPage{}, &plugin.WebError{Status: http.StatusForbidden, Message: "You do not have permission to do that."}
		}
		if msg := webMessage(err); msg != "" {
			val := r.PostFormValue("username")
			if form == "topic" {
				val = r.PostFormValue("topic")
			}
			return p.channelPage(r, s, c, "", map[string]string{form: msg}, map[string]string{form: val})
		}
		if err != nil {
			return plugin.WebPage{}, err
		}
		if done == "closed" {
			return plugin.WebPage{Redirect: s.Path("/?done=closed")}, nil
		}
		return plugin.WebPage{Redirect: s.Path("/c/"+strconv.FormatInt(c.ID, 10)+"?done="+done) + "#private-heading"}, nil
	}
}

func (p *Plugin) webInvite(r *http.Request, c Channel, u auth.User) error {
	acct, err := p.member(r.Context(), r.PostFormValue("username"))
	if err == nil && acct.Status != auth.StatusActive {
		err = fmt.Errorf("%w: %s's account is not active", ErrInvalid, acct.Username)
	}
	if err == nil {
		err = p.Invite(r.Context(), u.ID, c, acct.ID)
	}
	if err == nil {
		p.h.Log.Info("invited to private chat from the web", "channel_id", c.ID, "user_id", acct.ID, "actor", u.ID)
	}
	return err
}

func (p *Plugin) webTopic(r *http.Request, c Channel, u auth.User) error {
	return p.changeTopic(r.Context(), u, c, r.PostFormValue("topic"))
}

func (p *Plugin) webRemove(r *http.Request, c Channel, u auth.User) error {
	acct, err := p.member(r.Context(), r.PostFormValue("username"))
	if err == nil && acct.ID == u.ID {
		err = fmt.Errorf("%w: you cannot remove yourself; leave the chat instead", ErrInvalid)
	}
	if err != nil {
		return err
	}
	return p.remove(r.Context(), u, c, acct)
}

func (p *Plugin) webClose(r *http.Request, c Channel, u auth.User) error {
	if r.PostFormValue("confirm") != "yes" {
		return fmt.Errorf("%w: tick the box to confirm", ErrInvalid)
	}
	return p.Destroy(r.Context(), u.ID, c.ID)
}

// webNew shows the form to start a private chat.
func (p *Plugin) webNew(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	return p.newPage(s, "", nil)
}

func (p *Plugin) newPage(s plugin.WebSession, msg string, vals map[string]string) (plugin.WebPage, error) {
	body, err := execPage("new", map[string]any{
		"Error": msg, "Values": vals, "Action": s.Path("/new"), "CSRF": s.CSRF(), "MaxTopic": MaxTopic, "Back": s.Path("/"),
	})
	return plugin.WebPage{Title: "Start a private chat", Body: body}, err
}

// webCreate starts a private chat and opens it.
func (p *Plugin) webCreate(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	vals := map[string]string{"name": r.PostFormValue("name"), "invite": r.PostFormValue("invite"), "topic": r.PostFormValue("topic")}
	id, err := p.createAdHoc(r.Context(), s.UserID(), strings.TrimSpace(vals["name"]), vals["topic"], vals["invite"])
	if msg := webMessage(err); msg != "" {
		return p.newPage(s, msg, vals)
	}
	if err != nil {
		return plugin.WebPage{}, err
	}
	p.h.Log.Info("private chat started from the web", "channel_id", id, "actor", s.UserID())
	return plugin.WebPage{Redirect: s.Path("/c/" + strconv.FormatInt(id, 10))}, nil
}
