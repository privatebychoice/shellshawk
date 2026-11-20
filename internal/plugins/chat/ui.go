package chat

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

func clock(t time.Time) string { return t.UTC().Format("15:04") }

func messageLine(at time.Time, name, body string) tui.Line {
	return tui.Line{
		{Text: "[" + clock(at) + "] ", Style: theme.Style{FG: theme.Muted}},
		{Text: name, Style: theme.Style{FG: theme.Accent, Bold: true}},
		{Text: ": " + body},
	}
}

func eventLine(at time.Time, text string) tui.Line {
	return tui.Styled("["+clock(at)+"] * "+text, theme.Style{FG: theme.Muted})
}

// sentence turns an ErrInvalid or ErrSlowDown error into a sentence for
// the member: "invalid: the message is empty" → "The message is empty."
func sentence(err error) string {
	msg := strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")
	if msg == "" {
		return ""
	}
	return strings.ToUpper(msg[:1]) + msg[1:] + "."
}

func errorMessage(err error) string {
	switch {
	case errors.Is(err, perm.ErrForbidden):
		return "You do not have permission to do that."
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrExists), errors.Is(err, ErrNotFound):
		return err.Error() + "."
	}
	return ""
}

func (p *Plugin) run(ctx context.Context, s plugin.Session) error {
	for {
		chans, err := p.Accessible(ctx, s.UserID())
		if err != nil {
			return err
		}
		set, err := s.Permissions(ctx)
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		for _, c := range chans {
			items = append(items, tui.MenuItem{
				Value: strconv.FormatInt(c.ID, 10),
				Label: channelLabel(c, p.hub.count(c.ID)),
				Help:  c.Topic,
			})
		}
		var actions []tui.Action
		if len(chans) > 0 {
			actions = append(actions, tui.Action{Key: 'f', Value: "find", Label: "Find a channel"})
		}
		if set.Has(PermCreate) {
			actions = append(actions, tui.Action{Key: 'n', Value: "new", Label: "Start a private chat"})
		}
		if set.Has(PermCreate) && set.Has(PermPage) && p.h.Notify != nil {
			actions = append(actions, tui.Action{Key: 'a', Value: "page", Label: "Page someone"})
		}
		if set.Has(PermModerate) {
			actions = append(actions, tui.Action{Key: 'm', Value: "manage", Label: "Manage channels"})
		}
		intro := "[C] channel, [P] private chat, [T] conference thread chat."
		if len(chans) == 0 {
			intro = "There are no channels you can join."
		}
		choice, err := s.UI().Choose(ctx, tui.Menu{
			Title:   s.Title("Chat"),
			Intro:   intro,
			Items:   items,
			Actions: actions,
		})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "new":
			var id int64
			if id, err = p.createAdHocForm(ctx, s); err == nil {
				err = p.Enter(ctx, s, id)
			}
		case "page":
			err = p.pageForm(ctx, s)
		case "manage":
			err = p.manage(ctx, s)
		case "find":
			err = p.find(ctx, s)
		default:
			id, _ := strconv.ParseInt(choice, 10, 64)
			err = p.Enter(ctx, s, id)
		}
		if msg := errorMessage(err); msg != "" {
			err = tui.Message(ctx, s.UI(), s.Title("Chat"), msg)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func (p *Plugin) createAdHocForm(ctx context.Context, s plugin.Session) (int64, error) {
	fm := &form.Form{Title: "Start a private chat", Fields: []form.Field{
		{Name: "name", Label: "Name", Kind: form.SingleLine, Required: true, MaxLen: 32,
			Help: "Lowercase letters, digits and '-', starting with a letter."},
		{Name: "invite", Label: "Invite", Kind: form.SingleLine, MaxLen: 1000, Help: "Usernames, separated by commas. You can invite more later with /invite."},
		{Name: "topic", Label: "Topic", Kind: form.SingleLine, MaxLen: MaxTopic},
	}}
	vals, errs := form.Values{}, form.Errors{}
	for {
		v, err := s.Form(ctx, fm, vals, errs)
		if err != nil {
			return 0, err
		}
		vals = v
		id, err := p.createAdHoc(ctx, s.UserID(), v["name"], v["topic"], v["invite"])
		switch {
		case err == nil:
			return id, nil
		case errors.Is(err, ErrInvalid) && strings.Contains(err.Error(), "name"), errors.Is(err, ErrExists):
			errs = form.Errors{"name": err}
		case errors.Is(err, ErrInvalid) && strings.Contains(err.Error(), "topic"):
			errs = form.Errors{"topic": err}
		case errors.Is(err, ErrInvalid):
			errs = form.Errors{"invite": err}
		default:
			return 0, err
		}
	}
}

// createAdHoc creates a private chat and invites the listed usernames.
func (p *Plugin) createAdHoc(ctx context.Context, creator int64, name, topic, invite string) (int64, error) {
	var ids []int64
	for _, u := range strings.Split(invite, ",") {
		if strings.TrimSpace(u) == "" {
			continue
		}
		acct, err := p.member(ctx, u)
		if err != nil || acct.Status != auth.StatusActive {
			return 0, fmt.Errorf("%w: no active member called %q", ErrInvalid, strings.TrimPrefix(strings.TrimSpace(u), "@"))
		}
		// Check before creating, so a refusal leaves no empty chat behind.
		if err := p.mayInvite(ctx, creator, acct.ID); err != nil {
			return 0, err
		}
		ids = append(ids, acct.ID)
	}
	if max := p.intSetting(ctx, setMaxInvitees, defaultMaxInvitees); len(ids) > max {
		return 0, fmt.Errorf("%w: a private chat can have at most %d invitations", ErrInvalid, max)
	}
	id, err := p.Create(ctx, creator, NewChannel{Name: name, Kind: KindAdHoc, Topic: topic, RetentionDays: DefaultRetention})
	if err != nil {
		return 0, err
	}
	c, err := p.Get(ctx, id)
	if err != nil {
		return 0, err
	}
	for _, uid := range ids {
		if err := p.Invite(ctx, creator, c, uid); err != nil {
			return 0, err
		}
	}
	return id, nil
}

// member looks up a member by username ("@name" also works).
func (p *Plugin) member(ctx context.Context, name string) (auth.User, error) {
	name = strings.TrimPrefix(strings.TrimSpace(name), "@")
	acct, err := p.h.Auth.UserByUsername(ctx, name)
	if err != nil || name == "" {
		return auth.User{}, fmt.Errorf("%w: no member called %q", ErrInvalid, name)
	}
	return acct, nil
}

// changeTopic sets c's topic as u and announces it in the channel.
func (p *Plugin) changeTopic(ctx context.Context, u auth.User, c Channel, topic string) error {
	topic, err := cleanTopic(topic)
	if err != nil {
		return err
	}
	if err := p.SetTopic(ctx, u.ID, c, topic); err != nil {
		return err
	}
	now := p.now()
	ev := u.Username + " changed the topic to: " + topic
	if err := p.record(ctx, c, u.ID, "event", ev, now); err != nil {
		p.h.Log.Error("chat log write failed", "channel_id", c.ID, "err", err)
	}
	p.hub.broadcast(c.ID, eventLine(now, ev))
	return nil
}

// remove takes target out of c as u (see Kick) and announces it.
func (p *Plugin) remove(ctx context.Context, u auth.User, c Channel, target auth.User) error {
	if err := p.Kick(ctx, u.ID, c, target.ID); err != nil {
		return err
	}
	p.hub.broadcast(c.ID, eventLine(p.now(), target.Username+" was removed by "+u.Username))
	return nil
}

// Enter opens a channel. /join and /createchat switch channels without
// returning to the menu. Conferences uses Enter for thread chats.
func (p *Plugin) Enter(ctx context.Context, s plugin.Session, id int64) error {
	for id != 0 {
		next, err := p.enterOne(ctx, s, id)
		if err != nil {
			return err
		}
		id = next
	}
	return nil
}

// enterOne runs one channel and returns the channel to switch to, if any.
func (p *Plugin) enterOne(ctx context.Context, s plugin.Session, id int64) (int64, error) {
	c, err := p.Get(ctx, id)
	if err != nil {
		return 0, err
	}
	if ok, err := p.CanAccess(ctx, s.UserID(), c); err != nil || !ok {
		return 0, errors.Join(perm.ErrForbidden, err)
	}
	u, err := p.h.Auth.UserByID(ctx, s.UserID())
	if err != nil {
		return 0, err
	}
	hist, err := p.History(ctx, c, historyLines, time.Time{}, time.Time{})
	if err != nil {
		return 0, err
	}

	var history []tui.Line
	history = append(history, tui.Text(banner(c)))
	if len(hist) > 0 {
		history = append(history, tui.Text(fmt.Sprintf("Last %d logged line(s):", len(hist))))
	}
	for _, e := range hist {
		if e.Kind == "event" {
			history = append(history, eventLine(e.At, e.Body))
		} else {
			history = append(history, messageLine(e.At, e.Name, e.Body))
		}
	}

	m := p.hub.join(c.ID, u.ID, u.Username)
	watch, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	go p.watchAccess(watch, s.Log(), u.ID, c, m)
	p.hub.broadcast(c.ID, eventLine(p.now(), u.Username+" joined"))
	s.Log().Info("joined chat", "channel_id", c.ID)
	defer func() {
		p.hub.leave(c.ID, m)
		p.hub.broadcast(c.ID, eventLine(p.now(), u.Username+" left"))
		s.Log().Info("left chat", "channel_id", c.ID)
	}()

	var next int64
	err = s.UI().Live(ctx, tui.LiveRequest{
		Title:    s.Title(fmt.Sprintf("#%s %s", c.Name, c.Tag())),
		History:  history,
		Incoming: m.out,
		MaxLen:   MaxMessage,
		Submit: func(text string) ([]tui.Line, bool) {
			fb, leave, n := p.submit(ctx, s, u, c.ID, text)
			next = n
			return fb, leave
		},
	})
	return next, err
}

// watchAccess checks, while a member is in a channel over SSH, that they
// may still enter it, as the web stream does. A member who has lost access
// (removed from the channel's group, from a restricted conference, or
// without chat.use) is put out of the room with the reason, which ends
// their view as a kick does. It stops when ctx ends.
func (p *Plugin) watchAccess(ctx context.Context, log *slog.Logger, user int64, c Channel, m *member) {
	every := p.recheck
	if every <= 0 {
		every = keepAlive
	}
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		ok, err := p.CanAccess(ctx, user, c)
		if err != nil {
			if ctx.Err() == nil {
				log.Error("recheck chat access", "channel_id", c.ID, "err", err)
			}
			continue // a database hiccup is not a reason to put them out
		}
		if !ok {
			log.Info("left chat: access lost", "channel_id", c.ID)
			p.hub.evict(c.ID, m, "You no longer have access to #"+c.Name+".")
			return
		}
	}
}

// find searches the channels the member can enter and opens the one they
// pick.
func (p *Plugin) find(ctx context.Context, s plugin.Session) error {
	fm := &form.Form{Title: "Find a channel", Fields: []form.Field{{
		Name: "q", Label: "Channel name or topic, or part of one", Kind: form.SingleLine, Required: true, MaxLen: MaxTopic,
	}}}
	v, err := s.Form(ctx, fm, nil, nil)
	if err != nil {
		return err
	}
	found, err := p.FindAccessible(ctx, s.UserID(), v["q"])
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return tui.Message(ctx, s.UI(), s.Title("Find a channel"), "No channel you can join matches \""+strings.TrimSpace(v["q"])+"\".")
	}
	var items []tui.MenuItem
	for _, c := range found {
		items = append(items, tui.MenuItem{Value: strconv.FormatInt(c.ID, 10), Label: channelLabel(c, p.hub.count(c.ID)), Help: c.Topic})
	}
	choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title(fmt.Sprintf("Find a channel: %d match(es)", len(found))), Items: items})
	if err != nil {
		return err
	}
	id, _ := strconv.ParseInt(choice, 10, 64)
	return p.Enter(ctx, s, id)
}

// channelLabel is a channel's line in the chat list. Thread chats also show
// their topic (the thread title) so members can tell them apart.
func channelLabel(c Channel, here int) string {
	l := fmt.Sprintf("#%s %s (%d here)", c.Name, c.Tag(), here)
	if c.Kind == KindThread && c.Topic != "" {
		l += " " + c.Topic
	}
	return l
}

func banner(c Channel) string {
	b := fmt.Sprintf("#%s, %s.", c.Name, c.KindName())
	if c.Topic != "" {
		b += " Topic: " + c.Topic + "."
	}
	if c.RetentionDays == 0 {
		b += " This chat is not logged: messages are not saved."
	} else {
		b += fmt.Sprintf(" This chat is logged: messages are kept for %d days and members of this chat can download them over SFTP.", c.RetentionDays)
	}
	return b + " Times are UTC."
}

const helpText = `Commands:
/who                   who is here
/channels              channels you can join
/join NAME             switch to another channel
/topic [TEXT]          show or change the topic
/invite USER           let someone into this private chat
/page USER             ask someone to come and talk here
/kick USER             remove someone from this chat
/createchat NAME [USERS]  start a private chat, inviting USERS (comma-separated)
/destroychat           close this private chat for everyone
/quit                  leave`

// submit handles one entered line: a command or a message. It returns
// feedback for the sender, whether to leave, and a channel to switch to.
func (p *Plugin) submit(ctx context.Context, s plugin.Session, u auth.User, chID int64, text string) ([]tui.Line, bool, int64) {
	say := func(f string, a ...any) []tui.Line { return []tui.Line{tui.Text(fmt.Sprintf(f, a...))} }
	c, err := p.Get(ctx, chID)
	if err != nil {
		return say("This chat no longer exists."), true, 0
	}
	if ok, _ := p.CanAccess(ctx, u.ID, c); !ok {
		return say("You no longer have access to this chat."), true, 0
	}
	if !strings.HasPrefix(text, "/") {
		switch err := p.Say(ctx, c, u, text); {
		case err == nil:
		case errors.Is(err, ErrSlowDown), errors.Is(err, ErrInvalid):
			return say("%s", sentence(err)), false, 0
		default:
			s.Log().Error("chat log write failed", "err", err)
			return say("Your message could not be sent."), false, 0
		}
		return nil, false, 0
	}

	cmd, arg, _ := strings.Cut(text, " ")
	arg = strings.TrimSpace(arg)
	fail := func(err error) []tui.Line {
		if msg := errorMessage(err); msg != "" {
			return say("%s", msg)
		}
		s.Log().Error("chat command failed", "command", cmd, "err", err)
		return say("Sorry, that did not work.")
	}
	userArg := func() (auth.User, error) { return p.member(ctx, arg) }
	switch strings.ToLower(cmd) {
	case "/help":
		var out []tui.Line
		for _, l := range strings.Split(helpText, "\n") {
			out = append(out, tui.Text(l))
		}
		return out, false, 0
	case "/quit", "/leave", "/exit":
		return nil, true, 0
	case "/who":
		return say("In #%s: %s.", c.Name, strings.Join(p.hub.who(c.ID), ", ")), false, 0
	case "/channels":
		chans, err := p.Accessible(ctx, u.ID)
		if err != nil {
			return fail(err), false, 0
		}
		out := say("Channels you can join:")
		for _, ch := range chans {
			out = append(out, tui.Text(fmt.Sprintf("#%s %s, %d here. %s", ch.Name, ch.Tag(), p.hub.count(ch.ID), ch.Topic)))
		}
		return out, false, 0
	case "/join":
		ch, err := p.ByName(ctx, arg)
		if err != nil {
			return fail(err), false, 0
		}
		if ok, _ := p.CanAccess(ctx, u.ID, ch); !ok {
			return fail(ErrNotFound), false, 0 // do not reveal private chats
		}
		return nil, true, ch.ID
	case "/topic":
		if arg == "" {
			return say("Topic: %s", c.Topic), false, 0
		}
		if err := p.changeTopic(ctx, u, c, arg); err != nil {
			return fail(err), false, 0
		}
		return nil, false, 0
	case "/invite":
		acct, err := userArg()
		if err == nil {
			err = p.Invite(ctx, u.ID, c, acct.ID)
		}
		if err != nil {
			return fail(err), false, 0
		}
		return say("%s can now join #%s from the Chat menu.", acct.Username, c.Name), false, 0
	case "/page":
		acct, err := p.Page(ctx, u, arg, c)
		if err != nil {
			name := acct.Username
			if name == "" {
				name = strings.TrimPrefix(arg, "@")
			}
			if msg := pageMessage(name, err); msg != "" {
				return say("%s", msg), false, 0
			}
			return fail(err), false, 0
		}
		return say("%s has been paged to #%s.", acct.Username, c.Name), false, 0
	case "/kick":
		acct, err := userArg()
		if err == nil && acct.ID == u.ID {
			err = fmt.Errorf("%w: you cannot kick yourself; use /quit", ErrInvalid)
		}
		if err == nil {
			err = p.remove(ctx, u, c, acct)
		}
		if err != nil {
			return fail(err), false, 0
		}
		return nil, false, 0
	case "/createchat":
		name, users, _ := strings.Cut(arg, " ")
		id, err := p.createAdHoc(ctx, u.ID, name, "", users)
		if err != nil {
			return fail(err), false, 0
		}
		return nil, true, id
	case "/destroychat":
		if c.Kind != KindAdHoc {
			return say("Only private chats can be closed with /destroychat. Moderators manage channels from the Chat menu."), false, 0
		}
		if err := p.Destroy(ctx, u.ID, c.ID); err != nil {
			return fail(err), false, 0
		}
		return nil, true, 0
	}
	return say("Unknown command %s. Type /help for the list.", cmd), false, 0
}

// manage lets chat moderators create, configure and delete persistent
// channels.
func (p *Plugin) manage(ctx context.Context, s plugin.Session) error {
	chans, err := p.Accessible(ctx, s.UserID())
	if err != nil {
		return err
	}
	var items []tui.MenuItem
	for _, c := range chans {
		items = append(items, tui.MenuItem{Value: strconv.FormatInt(c.ID, 10), Label: "#" + c.Name + " " + c.Tag(),
			Help: fmt.Sprintf("Logged for %d day(s)", c.RetentionDays)})
	}
	choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Manage channels"), Items: items,
		Actions: []tui.Action{{Key: 'n', Value: "new", Label: "Create a channel"}}})
	if err != nil {
		return err
	}
	if choice == "new" {
		groups, err := p.h.Perms.Groups(ctx)
		if err != nil {
			return err
		}
		var groupOpts []form.Option
		for _, g := range groups {
			label := g.Name
			if g.Description != "" {
				label += ": " + g.Description
			}
			groupOpts = append(groupOpts, form.Option{Value: strconv.FormatInt(g.ID, 10), Label: label})
		}
		fm := &form.Form{Title: "Create a channel", Fields: []form.Field{
			{Name: "name", Label: "Name", Kind: form.SingleLine, Required: true, MaxLen: 32},
			{Name: "topic", Label: "Topic", Kind: form.SingleLine, MaxLen: MaxTopic},
			{Name: "groups", Label: "Only these groups can join", Kind: form.Choice, Multi: true, Options: groupOpts,
				Help: "Choose none to open it to everyone who can chat. Choose one or more groups to make it members-only: anyone in any chosen group can join. Administrators can always join."},
			{Name: "days", Label: "Keep the log for this many days (0 = do not log)", Kind: form.SingleLine, Subtype: form.Int,
				Required: true, Min: form.Bound(0), Max: form.Bound(MaxRetention)},
		}}
		v, err := s.Form(ctx, fm, form.Values{"days": strconv.Itoa(DefaultRetention)}, nil)
		if err != nil {
			return err
		}
		var ids []int64
		for _, g := range strings.Split(v["groups"], ",") {
			if id, err := strconv.ParseInt(g, 10, 64); err == nil {
				ids = append(ids, id)
			}
		}
		days, _ := strconv.Atoi(v["days"])
		if _, err := p.Create(ctx, s.UserID(), NewChannel{Name: v["name"], Kind: KindPersistent, Topic: v["topic"], Groups: ids, RetentionDays: days}); err != nil {
			return err
		}
		return tui.Message(ctx, s.UI(), s.Title("Manage channels"), "Channel created.")
	}
	id, _ := strconv.ParseInt(choice, 10, 64)
	c, err := p.Get(ctx, id)
	if err != nil {
		return err
	}
	action, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("#" + c.Name), Intro: banner(c), Items: []tui.MenuItem{
		{Value: "retention", Label: "Change how long the log is kept"},
		{Value: "delete", Label: "Delete this channel and its log"},
	}})
	if err != nil {
		return err
	}
	if action == "delete" {
		ok, err := tui.Confirm(ctx, s.UI(), s.Title("#"+c.Name), "Delete #"+c.Name+" and its whole log? Anyone inside is removed.")
		if err != nil || !ok {
			return err
		}
		return p.Destroy(ctx, s.UserID(), c.ID)
	}
	fm := &form.Form{Title: "Log retention for #" + c.Name, Fields: []form.Field{{
		Name: "days", Label: "Keep the log for this many days (0 = stop logging and delete the log)", Kind: form.SingleLine,
		Subtype: form.Int, Required: true, Min: form.Bound(0), Max: form.Bound(MaxRetention),
	}}}
	v, err := s.Form(ctx, fm, form.Values{"days": strconv.Itoa(c.RetentionDays)}, nil)
	if err != nil {
		return err
	}
	days, _ := strconv.Atoi(v["days"])
	return p.SetRetention(ctx, s.UserID(), c, days)
}
