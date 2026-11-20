package chat

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/plugin"
)

// keepAlive is how often an idle stream sends a comment (so proxies keep
// it open) and re-checks that the member may still be in the channel.
const keepAlive = 25 * time.Second

var panelTmpl = template.Must(template.New("panel").Parse(`<section class="live" id="chat" aria-labelledby="chat-heading" data-live-events="{{.Events}}">
<h2 id="chat-heading">{{.Heading}}</h2>
<p class="meta">{{.Banner}} {{.Here}}</p>
<ol class="chat-log" data-live-log role="log" aria-label="Chat messages" tabindex="0">
{{- range .Lines}}<li>{{.}}</li>{{else}}<li class="meta" data-live-empty>{{.Empty}}</li>{{end -}}
</ol>
<p class="meta" data-live-status role="status"></p>
<form method="post" action="{{.Send}}" data-live-form>
<input type="hidden" name="csrf" value="{{.CSRF}}">
<input type="hidden" name="return" value="{{.Return}}">
<label for="chat-message">Message</label>
<input type="text" id="chat-message" name="message" maxlength="{{.Max}}" required autocomplete="off">
<button type="submit">Send</button>
</form>
<noscript><p class="meta">New messages appear when you reload the page.</p></noscript>
</section>`))

func (p *Plugin) webRoutes() []plugin.WebRoute {
	use, create := []string{PermUse}, []string{PermCreate}
	return []plugin.WebRoute{
		{Path: "/", AnyOf: use, Handle: p.webList},
		{Path: "/find", AnyOf: use, Handle: p.webFind},
		{Path: "/new", AnyOf: create, Handle: p.webNew},
		{Path: "/new", Method: http.MethodPost, AnyOf: create, Handle: p.webCreate},
		{Path: "/c/{id}", AnyOf: use, Handle: p.webChannelPage},
		{Path: "/c/{id}/events", AnyOf: use, Stream: p.webEvents},
		{Path: "/c/{id}/send", Method: http.MethodPost, AnyOf: use, Handle: p.webSend},
		{Path: "/c/{id}/invite", Method: http.MethodPost, AnyOf: use, Handle: p.privateAction("invite", "invite", p.webInvite)},
		{Path: "/c/{id}/topic", Method: http.MethodPost, AnyOf: use, Handle: p.privateAction("topic", "topic", p.webTopic)},
		{Path: "/c/{id}/remove", Method: http.MethodPost, AnyOf: use, Handle: p.privateAction("remove", "remove", p.webRemove)},
		{Path: "/c/{id}/close", Method: http.MethodPost, AnyOf: use, Handle: p.privateAction("close", "closed", p.webClose)},
		{Path: "/c/{id}/page", Method: http.MethodPost, AnyOf: []string{PermPage}, Handle: p.webPageHere},
		{Path: "/page", AnyOf: []string{PermPage}, Handle: p.webPageForm},
		{Path: "/page", Method: http.MethodPost, AnyOf: []string{PermPage}, Handle: p.webPageTalk},
	}
}

// webChannel loads the channel in the URL and the member, reporting
// channels they may not enter as not found.
func (p *Plugin) webChannel(r *http.Request, s plugin.WebSession) (Channel, auth.User, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return Channel{}, auth.User{}, plugin.ErrWebNotFound
	}
	c, err := p.Get(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		return Channel{}, auth.User{}, plugin.ErrWebNotFound
	}
	if err != nil {
		return Channel{}, auth.User{}, err
	}
	if ok, err := p.CanAccess(r.Context(), s.UserID(), c); err != nil || !ok {
		return Channel{}, auth.User{}, errors.Join(plugin.ErrWebNotFound, err)
	}
	u, err := p.h.Auth.UserByID(r.Context(), s.UserID())
	return c, u, err
}

// webSend posts a message from the web panel.
func (p *Plugin) webSend(r *http.Request, s plugin.WebSession) (plugin.WebPage, error) {
	c, u, err := p.webChannel(r, s)
	if err != nil {
		return plugin.WebPage{}, err
	}
	text := r.PostFormValue("message")
	if strings.HasPrefix(strings.TrimSpace(text), "/") {
		return plugin.WebPage{}, &plugin.WebError{Status: http.StatusBadRequest,
			Message: "Commands such as /who only work in the SSH chat."}
	}
	switch err := p.Say(r.Context(), c, u, text); {
	case errors.Is(err, ErrSlowDown):
		return plugin.WebPage{}, &plugin.WebError{Status: http.StatusTooManyRequests, Message: sentence(err)}
	case errors.Is(err, ErrInvalid):
		return plugin.WebPage{}, &plugin.WebError{Status: http.StatusBadRequest, Message: sentence(err)}
	case err != nil:
		return plugin.WebPage{}, err
	}
	back := r.PostFormValue("return")
	if back != "" {
		back += "#chat"
	}
	return plugin.WebPage{Redirect: back}, nil
}

// writeEvent writes one server-sent event. data is kept to one line.
func writeEvent(w io.Writer, event, data string) error {
	data = strings.NewReplacer("\r", " ", "\n", " ").Replace(data)
	_, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
	return err
}

// webEvents streams a channel to the web panel: the member is in the
// channel (listed by /who) while the stream is open.
func (p *Plugin) webEvents(w http.ResponseWriter, r *http.Request, s plugin.WebSession) error {
	ctx := r.Context()
	c, u, err := p.webChannel(r, s)
	if err != nil {
		return err
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no") // tell reverse proxies not to buffer
	w.WriteHeader(http.StatusOK)
	flush := func() {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}

	m := p.hub.joinAs(c.ID, u.ID, u.Username, true)
	p.hub.broadcast(c.ID, eventLine(p.now(), u.Username+" joined"))
	p.h.Log.Info("joined chat from the web", "channel_id", c.ID, "user_id", u.ID)
	defer func() {
		p.hub.leave(c.ID, m)
		p.hub.broadcast(c.ID, eventLine(p.now(), u.Username+" left"))
		p.h.Log.Info("left chat from the web", "channel_id", c.ID, "user_id", u.ID)
	}()

	if _, err := io.WriteString(w, "retry: 5000\n\n"); err != nil {
		return err
	}
	flush()
	tick := time.NewTicker(keepAlive)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case l, ok := <-m.out:
			if !ok { // kicked or the chat was closed; the reason came as a line
				err := writeEvent(w, "end", "")
				flush()
				return err
			}
			if err := writeEvent(w, "line", l.Plain()); err != nil {
				return err
			}
		case <-tick.C:
			if ok, err := p.CanAccess(ctx, u.ID, c); err != nil || !ok {
				werr := writeEvent(w, "end", "You no longer have access to this chat.")
				flush()
				return errors.Join(err, werr)
			}
			if _, err := io.WriteString(w, ": keep-alive\n\n"); err != nil {
				return err
			}
		}
		flush()
	}
}

// WebPanel returns a live chat panel for embedding in another plugin's web
// page (e.g. a conference thread), or "" if user may not enter the
// channel. returnTo is the page to come back to after sending without
// JavaScript; csrf is the session's token (plugin.WebSession.CSRF).
func (p *Plugin) WebPanel(ctx context.Context, user, channel int64, heading, csrf, returnTo string) (template.HTML, error) {
	c, err := p.Get(ctx, channel)
	if errors.Is(err, ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if ok, err := p.CanAccess(ctx, user, c); err != nil || !ok {
		return "", err
	}
	hist, err := p.History(ctx, c, historyLines, time.Time{}, time.Time{})
	if err != nil {
		return "", err
	}
	var lines []string
	for _, e := range hist {
		if e.Kind == "event" {
			lines = append(lines, eventLine(e.At, e.Body).Plain())
		} else {
			lines = append(lines, messageLine(e.At, e.Name, e.Body).Plain())
		}
	}
	empty := "No messages yet."
	if c.RetentionDays == 0 {
		empty = "Earlier messages are not shown because this chat is not logged."
	}
	here := "Nobody else is here right now."
	if who := p.hub.who(c.ID); len(who) > 0 {
		here = "Here now: " + strings.Join(who, ", ") + "."
	}
	base := "/p/chat/c/" + strconv.FormatInt(c.ID, 10)
	var b bytes.Buffer
	err = panelTmpl.Execute(&b, map[string]any{
		"Heading": heading, "Banner": banner(c), "Here": here, "Lines": lines, "Empty": empty,
		"Events": base + "/events", "Send": base + "/send", "CSRF": csrf, "Return": returnTo, "Max": MaxMessage,
	})
	return template.HTML(b.String()), err //nolint:gosec // html/template output
}
