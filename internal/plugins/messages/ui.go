package messages

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

func fmtTime(m Summary) string { return m.CreatedAt.UTC().Format("2006-01-02 15:04 UTC") }

func (p *Plugin) run(ctx context.Context, s plugin.Session) error {
	for {
		c, err := p.Count(ctx, s.UserID())
		if err != nil {
			return err
		}
		set, err := s.Permissions(ctx)
		if err != nil {
			return err
		}
		items := []tui.MenuItem{
			{Value: Inbox, Label: fmt.Sprintf("Inbox (%d unread)", c.Unread)},
			{Value: Sent, Label: "Sent messages"},
			{Value: Deleted, Label: fmt.Sprintf("Deleted messages (%d)", c.Deleted)},
		}
		var actions []tui.Action
		if set.Has(PermSend) {
			actions = append(actions, tui.Action{Key: 'w', Value: "write", Label: "Write a message"})
		}
		choice, err := s.UI().Choose(ctx, tui.Menu{
			Title:   s.Title("Messages"),
			Intro:   fmt.Sprintf("Inbox: %d unread, %d read. Deleted: %d.", c.Unread, c.Read, c.Deleted),
			Items:   items,
			Actions: actions,
		})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		if choice == "write" {
			err = p.compose(ctx, s, Draft{}, form.Errors{})
		} else {
			err = p.folder(ctx, s, choice)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func (p *Plugin) folder(ctx context.Context, s plugin.Session, folder string) error {
	titles := map[string]string{Inbox: "Inbox", Sent: "Sent messages", Deleted: "Deleted messages"}
	for {
		list, err := p.List(ctx, s.UserID(), folder)
		if err != nil {
			return err
		}
		if len(list) == 0 {
			return tui.Message(ctx, s.UI(), s.Title(titles[folder]), "There are no messages here.")
		}
		var items []tui.MenuItem
		var actions []tui.Action
		intro := ""
		if folder == Deleted {
			intro = fmt.Sprintf("Messages here are removed permanently after %d days. You can move them back to the inbox until then.", p.DeletedDays(ctx))
			actions = append(actions, tui.Action{Key: 'e', Value: "empty", Label: "Empty the Deleted folder"})
		}
		for _, m := range list {
			label := m.Subject
			if !m.Read {
				label = "New: " + label // stated in words, not only by colour
			}
			who := "from " + m.From
			if folder == Sent {
				who = "to " + strings.Join(m.To, ", ")
			}
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(m.ID, 10), Label: label, Help: who + ", " + fmtTime(m)})
		}
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title(titles[folder]), Intro: intro, Items: items, Actions: actions})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		if choice == "empty" {
			ok, err := tui.Confirm(ctx, s.UI(), s.Title(titles[folder]), fmt.Sprintf("Remove all %d deleted message(s) permanently? This cannot be undone.", len(list)))
			if err != nil {
				return err
			}
			if ok {
				if _, err := p.EmptyDeleted(ctx, s.UserID()); err != nil {
					return err
				}
			}
			continue
		}
		id, _ := strconv.ParseInt(choice, 10, 64)
		if err := p.view(ctx, s, id, folder); err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

// render shows a message as markdown with a header.
func (p *Plugin) render(s plugin.Session, m Message) tui.Page {
	head := fmt.Sprintf("From: %s  \nTo: %s  \nDate: %s  \nSubject: %s\n\n---\n\n",
		escape(m.From), escape(strings.Join(m.To, ", ")), fmtTime(m.Summary), escape(m.Subject))
	return s.Markdown(s.Title("Message"), head+m.Body)
}

// escape stops header values (usernames, subjects) being read as markdown.
func escape(v string) string {
	r := strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "`", "\\`", "[", `\[`, "]", `\]`, "<", `\<`, "#", `\#`, "~", `\~`)
	return r.Replace(v)
}

// view shows a message opened from folder, which decides what Delete does
// (a message sent to oneself is in both Inbox and Sent).
func (p *Plugin) view(ctx context.Context, s plugin.Session, id int64, folder string) error {
	m, err := p.Read(ctx, s.UserID(), id)
	if err != nil {
		return err
	}
	if err := s.UI().Show(ctx, p.render(s, m)); err != nil {
		return err
	}
	set, err := s.Permissions(ctx)
	if err != nil {
		return err
	}
	var items []tui.MenuItem
	if set.Has(PermSend) && m.SenderID != 0 && m.Role == RoleRecipient {
		items = append(items, tui.MenuItem{Value: "reply", Label: "Reply"})
	}
	switch folder {
	case Deleted:
		items = append(items, tui.MenuItem{Value: "restore", Label: "Move back to the inbox"},
			tui.MenuItem{Value: "forever", Label: "Delete permanently"})
	case Sent:
		items = append(items, tui.MenuItem{Value: "delete", Label: "Remove from Sent"})
	default:
		items = append(items, tui.MenuItem{Value: "delete", Label: "Delete"})
	}
	action, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Message"), Intro: m.Subject, Items: items})
	if err != nil {
		return err
	}
	switch action {
	case "reply":
		return p.compose(ctx, s, replyDraft(m), form.Errors{})
	case "delete":
		return p.Delete(ctx, s.UserID(), m.ID, folder)
	case "restore":
		return p.Restore(ctx, s.UserID(), m.ID)
	case "forever":
		ok, err := tui.Confirm(ctx, s.UI(), s.Title("Message"), "Delete this message permanently? This cannot be undone.")
		if err != nil || !ok {
			return err
		}
		return p.DeleteForever(ctx, s.UserID(), m.ID)
	}
	return nil
}

// replyDraft starts a reply to m: back to its sender, "Re: " subject, the
// original quoted.
func replyDraft(m Message) Draft {
	subject := m.Subject
	if !strings.HasPrefix(strings.ToLower(subject), "re:") {
		subject = "Re: " + subject
	}
	if len([]rune(subject)) > MaxSubject {
		subject = string([]rune(subject)[:MaxSubject])
	}
	quoted := m.From + " wrote:\n\n> " + strings.ReplaceAll(m.Body, "\n", "\n> ") + "\n\n"
	return Draft{To: m.From, Subject: subject, Body: quoted, ParentID: m.ID}
}

// compose collects recipients and subject with a form, then the body with
// the editor, and sends.
func (p *Plugin) compose(ctx context.Context, s plugin.Session, d Draft, errs form.Errors) error {
	groups, err := p.contacts.Groups(ctx, s.UserID())
	if err != nil {
		return err
	}
	fields := []form.Field{
		{Name: "to", Label: "To", Kind: form.SingleLine, MaxLen: 1000,
			Help: "Usernames, separated by commas."},
	}
	if len(groups) > 0 {
		var opts []form.Option
		for _, g := range groups {
			opts = append(opts, form.Option{Value: g.Name, Label: fmt.Sprintf("%s (%d)", g.Name, g.Members)})
		}
		fields = append(fields, form.Field{Name: "groups", Label: "Contact groups", Kind: form.Choice, Multi: true, Options: opts,
			Help: "Also send to everyone in these groups."})
	}
	fields = append(fields, form.Field{Name: "subject", Label: "Subject", Kind: form.SingleLine, Required: true, MaxLen: MaxSubject})
	fm := &form.Form{Title: "Write a message", Fields: fields, Check: func(v form.Values) map[string]error {
		if strings.TrimSpace(v["to"]) == "" && v["groups"] == "" {
			return map[string]error{"to": ErrNoneToSend}
		}
		return nil
	}}
	vals := form.Values{"to": d.To, "subject": d.Subject, "groups": strings.Join(d.ContactGroups, ",")}
	body := d.Body
	for {
		v, err := s.Form(ctx, fm, vals, errs)
		if err != nil {
			return err
		}
		vals = v
		body, err = s.UI().Edit(ctx, tui.EditRequest{
			Title: s.Title("Message: " + v["subject"]), Text: body, MaxLen: p.MaxBody(ctx),
			Preview: func(t string) tui.Page { return s.Markdown(s.Title("Preview"), t) },
		})
		if err != nil {
			return err
		}
		draft := Draft{To: v["to"], Subject: v["subject"], Body: body, ParentID: d.ParentID}
		if v["groups"] != "" {
			draft.ContactGroups = strings.Split(v["groups"], ",")
		}
		_, err = p.Send(ctx, s.UserID(), draft)
		var re *RecipientError
		switch {
		case err == nil:
			return tui.Message(ctx, s.UI(), s.Title("Messages"), "Message sent.")
		case errors.As(err, &re), errors.Is(err, ErrNoneToSend):
			errs = form.Errors{"to": err}
		case errors.Is(err, ErrInvalid):
			field := errors.New(strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
			if strings.Contains(err.Error(), "subject") {
				errs = form.Errors{"subject": field}
			} else if strings.Contains(err.Error(), "recipients") {
				errs = form.Errors{"to": field}
			} else {
				if err := tui.Message(ctx, s.UI(), s.Title("Messages"), tui.Sentence(err, ErrInvalid)); err != nil {
					return err
				}
				errs = form.Errors{}
			}
		case errors.Is(err, perm.ErrForbidden):
			return tui.Message(ctx, s.UI(), s.Title("Messages"), "You do not have permission to send messages.")
		case errors.Is(err, ErrRateLimit):
			return tui.Message(ctx, s.UI(), s.Title("Messages"), tui.Sentence(err))
		default:
			return err
		}
	}
}

// Compose opens the message form addressed to "to" (usernames). Other
// plugins use it, e.g. "Send a message" on a member's profile.
func (p *Plugin) Compose(ctx context.Context, s plugin.Session, to string) error {
	if err := p.h.Perms.Require(ctx, s.UserID(), PermSend); err != nil {
		return err
	}
	return p.compose(ctx, s, Draft{To: to}, form.Errors{})
}

// CanSend reports whether the member may send messages.
func (p *Plugin) CanSend(ctx context.Context, user int64) bool {
	ok, err := p.h.Perms.Has(ctx, user, PermSend)
	return err == nil && ok
}
