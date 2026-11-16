package conferences

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/polls"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

func message(err error) string {
	switch {
	case errors.Is(err, perm.ErrForbidden):
		return "You do not have permission to do that."
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrLocked), errors.Is(err, ErrNotFound), errors.Is(err, ErrNotEmpty), errors.Is(err, ErrExists):
		return err.Error() + "."
	}
	return ""
}

// report shows expected errors as a message and passes others on.
func report(ctx context.Context, s plugin.Session, err error) error {
	if msg := message(err); msg != "" {
		return tui.Message(ctx, s.UI(), s.Title("Conferences"), msg)
	}
	if errors.Is(err, tui.ErrCancelled) {
		return nil
	}
	return err
}

func (p *Plugin) run(ctx context.Context, s plugin.Session) error {
	for {
		areas, err := p.Areas(ctx)
		if err != nil {
			return err
		}
		set, err := s.Permissions(ctx)
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		for _, a := range areas {
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(a.ID, 10), Label: a.Name, Help: a.Description})
		}
		if set.Has(PermModerate) {
			items = append(items, tui.MenuItem{Value: "newarea", Label: "Create an area"})
		}
		items = append(items, tui.MenuItem{Value: "back", Label: "Back"})
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Conferences"), Intro: "Choose an area.", Items: items})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		if choice == "newarea" {
			err = p.areaForm(ctx, s)
		} else {
			id, _ := strconv.ParseInt(choice, 10, 64)
			for _, a := range areas {
				if a.ID == id {
					err = p.area(ctx, s, a)
				}
			}
		}
		if err = report(ctx, s, err); err != nil {
			return err
		}
	}
}

func slugFields(what string) []form.Field {
	return []form.Field{
		{Name: "slug", Label: "Short name", Kind: form.SingleLine, Required: true, MaxLen: 32,
			Help: "Used in SFTP paths: lowercase letters, digits and '-', starting with a letter."},
		{Name: "name", Label: what + " name", Kind: form.SingleLine, Required: true, MaxLen: MaxName},
		{Name: "desc", Label: "Description", Kind: form.SingleLine, MaxLen: MaxDescription},
	}
}

func (p *Plugin) areaForm(ctx context.Context, s plugin.Session) error {
	v, err := s.Form(ctx, &form.Form{Title: "Create an area", Fields: slugFields("Area")}, nil, nil)
	if err != nil {
		return err
	}
	_, err = p.CreateArea(ctx, s.UserID(), v["slug"], v["name"], v["desc"])
	return err
}

func (p *Plugin) area(ctx context.Context, s plugin.Session, a Area) error {
	for {
		confs, err := p.Conferences(ctx, s.UserID(), a.ID)
		if err != nil {
			return err
		}
		set, err := s.Permissions(ctx)
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		for _, c := range confs {
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(c.ID, 10), Label: c.Name, Help: c.Description})
		}
		if set.Has(PermModerate) {
			items = append(items, tui.MenuItem{Value: "newconf", Label: "Create a conference"})
			if len(confs) == 0 {
				items = append(items, tui.MenuItem{Value: "delarea", Label: "Delete this area"})
			}
		}
		items = append(items, tui.MenuItem{Value: "back", Label: "Back"})
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title(a.Name), Intro: a.Description, Items: items})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "newconf":
			err = p.conferenceForm(ctx, s, a)
		case "delarea":
			ok, cerr := tui.Confirm(ctx, s.UI(), s.Title(a.Name), "Delete the empty area "+a.Name+"?")
			if cerr != nil || !ok {
				err = cerr
				break
			}
			if err = p.DeleteArea(ctx, s.UserID(), a.ID); err == nil {
				return nil
			}
		default:
			id, _ := strconv.ParseInt(choice, 10, 64)
			err = p.conference(ctx, s, id)
		}
		if err = report(ctx, s, err); err != nil {
			return err
		}
	}
}

func (p *Plugin) conferenceForm(ctx context.Context, s plugin.Session, a Area) error {
	opts := []form.Option{{Value: "none", Label: "Everyone who can read conferences"}}
	for _, pm := range p.h.Perms.Registry().All() {
		opts = append(opts, form.Option{Value: pm.Name, Label: pm.Name + ": " + pm.Description})
	}
	fields := append(slugFields("Conference"), form.Field{
		Name: "perm", Label: "Who can read and post", Kind: form.Choice, Required: true, Options: opts,
		Help: "Members also need this permission. Grant it to a group to make a group-only conference.",
	})
	v, err := s.Form(ctx, &form.Form{Title: "Create a conference in " + a.Name, Fields: fields}, form.Values{"perm": "none"}, nil)
	if err != nil {
		return err
	}
	pm := v["perm"]
	if pm == "none" {
		pm = ""
	}
	_, err = p.CreateConference(ctx, s.UserID(), a.ID, v["slug"], v["name"], v["desc"], pm)
	return err
}

func (p *Plugin) conference(ctx context.Context, s plugin.Session, id int64) error {
	for {
		c, set, err := p.access(ctx, s.UserID(), id)
		if err != nil {
			return err
		}
		threads, err := p.Threads(ctx, s.UserID(), id)
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		if canPost(set, c) {
			items = append(items, tui.MenuItem{Value: "new", Label: "Start a thread"})
		}
		for _, t := range threads {
			label := t.Title
			if t.Locked {
				label += " (locked)"
			}
			items = append(items, tui.MenuItem{
				Value: strconv.FormatInt(t.ID, 10), Label: label,
				Help: fmt.Sprintf("by %s, %d post(s), last %s", t.Author, t.Posts, t.LastPostAt.UTC().Format("2006-01-02 15:04 UTC")),
			})
		}
		if set.Has(PermModerate) {
			items = append(items, tui.MenuItem{Value: "delconf", Label: "Delete this conference"})
		}
		items = append(items, tui.MenuItem{Value: "back", Label: "Back"})
		intro := fmt.Sprintf("%s %d thread(s).", c.Description, len(threads))
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title(c.Name), Intro: strings.TrimSpace(intro), Items: items})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "new":
			err = p.newThread(ctx, s, c)
		case "delconf":
			ok, cerr := tui.Confirm(ctx, s.UI(), s.Title(c.Name), "Delete "+c.Name+" with all its threads, posts, polls and thread chats?")
			if cerr != nil || !ok {
				err = cerr
				break
			}
			if err = p.DeleteConference(ctx, s.UserID(), c.ID); err == nil {
				return nil
			}
		default:
			tid, _ := strconv.ParseInt(choice, 10, 64)
			err = p.thread(ctx, s, tid)
		}
		if err = report(ctx, s, err); err != nil {
			return err
		}
	}
}

func (p *Plugin) editor(ctx context.Context, s plugin.Session, title, text string) (string, error) {
	return s.UI().Edit(ctx, tui.EditRequest{
		Title: s.Title(title), Text: text, MaxLen: p.maxBody(ctx),
		Preview: func(t string) tui.Page { return s.Markdown(s.Title("Preview"), t) },
	})
}

func (p *Plugin) newThread(ctx context.Context, s plugin.Session, c Conference) error {
	fm := &form.Form{Title: "Start a thread in " + c.Name, Fields: []form.Field{
		{Name: "title", Label: "Title", Kind: form.SingleLine, Required: true, MaxLen: MaxTitle},
	}}
	v, err := s.Form(ctx, fm, nil, nil)
	if err != nil {
		return err
	}
	body, err := p.editor(ctx, s, v["title"], "")
	if err != nil {
		return err
	}
	tid, pid, err := p.StartThread(ctx, s.UserID(), c.ID, v["title"], body)
	if err != nil {
		return err
	}
	if err := p.offerPoll(ctx, s, pid); err != nil {
		return err
	}
	return p.thread(ctx, s, tid)
}

// offerPoll asks whether to attach a poll to a new post.
func (p *Plugin) offerPoll(ctx context.Context, s plugin.Session, post int64) error {
	if p.canAddPoll(ctx, s.UserID(), post) != nil {
		return nil
	}
	ok, err := tui.Confirm(ctx, s.UI(), s.Title("Posted"), "Your post is published. Add a poll to it?")
	if err != nil || !ok {
		return err
	}
	_, err = p.polls.CreateForm(ctx, s, pollContext(post))
	return err
}

// render shows the whole thread as one markdown document.
func (p *Plugin) render(t Thread, posts []Post) string {
	var b strings.Builder
	for i, po := range posts {
		fmt.Fprintf(&b, "### Post %d of %d, by %s, %s", i+1, len(posts), escape(po.Author), po.CreatedAt.UTC().Format("2006-01-02 15:04 UTC"))
		if po.EditedAt != nil {
			b.WriteString(" (edited)")
		}
		b.WriteString("\n\n" + po.Body + "\n\n")
		if len(po.Polls) > 0 {
			fmt.Fprintf(&b, "*This post has %d poll(s): choose Polls in this thread.*\n\n", len(po.Polls))
		}
		if i < len(posts)-1 {
			b.WriteString("---\n\n")
		}
	}
	if t.Locked {
		b.WriteString("\n*This thread is locked: no new replies.*\n")
	}
	return b.String()
}

func escape(v string) string {
	return strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "`", "\\`", "[", `\[`, "]", `\]`, "<", `\<`, "#", `\#`, "~", `\~`).Replace(v)
}

func (p *Plugin) thread(ctx context.Context, s plugin.Session, id int64) error {
	show := true
	for {
		t, c, set, err := p.Thread(ctx, s.UserID(), id)
		if err != nil {
			return err
		}
		posts, err := p.Posts(ctx, s.UserID(), id)
		if err != nil {
			return err
		}
		if show {
			if err := s.UI().Show(ctx, s.Markdown(s.Title(t.Title), p.render(t, posts))); err != nil {
				return err
			}
			show = false
		}
		var mine, editable []Post
		var withPolls int
		for _, po := range posts {
			if canEdit(set, s.UserID(), po, t) {
				editable = append(editable, po)
			}
			if po.AuthorID == s.UserID() {
				mine = append(mine, po)
			}
			withPolls += len(po.Polls)
		}
		items := []tui.MenuItem{{Value: "read", Label: "Read the thread again"}}
		if canPost(set, c) && !t.Locked {
			items = append(items, tui.MenuItem{Value: "reply", Label: "Reply"})
		}
		if withPolls > 0 {
			items = append(items, tui.MenuItem{Value: "polls", Label: fmt.Sprintf("Polls in this thread (%d)", withPolls)})
		}
		if len(editable) > 0 {
			items = append(items, tui.MenuItem{Value: "edit", Label: "Edit a post"}, tui.MenuItem{Value: "delete", Label: "Delete a post"})
		}
		if p.polls != nil && len(mine) > 0 && set.Has(polls.PermCreate) && !t.Locked {
			items = append(items, tui.MenuItem{Value: "addpoll", Label: "Add a poll to one of my posts"})
		}
		if t.ChatChannelID != 0 && p.chat != nil {
			items = append(items, tui.MenuItem{Value: "chat", Label: "Join the thread chat"})
		}
		if set.Has(PermModerate) {
			if t.Locked {
				items = append(items, tui.MenuItem{Value: "unlock", Label: "Unlock thread"})
			} else {
				items = append(items, tui.MenuItem{Value: "lock", Label: "Lock thread"})
			}
			if t.ChatChannelID == 0 && p.chat != nil {
				items = append(items, tui.MenuItem{Value: "enablechat", Label: "Enable a chat for this thread"})
			}
			items = append(items, tui.MenuItem{Value: "delthread", Label: "Delete thread"})
		}
		items = append(items, tui.MenuItem{Value: "back", Label: "Back"})
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title(t.Title), Intro: fmt.Sprintf("%d post(s) in %s.", len(posts), c.Name), Items: items})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "read":
			show = true
		case "reply":
			var body string
			if body, err = p.editor(ctx, s, "Reply: "+t.Title, ""); err == nil {
				var pid int64
				if pid, err = p.Reply(ctx, s.UserID(), id, body); err == nil {
					err = p.offerPoll(ctx, s, pid)
					show = true
				}
			}
		case "polls":
			err = p.choosePoll(ctx, s, posts)
		case "edit", "delete", "addpoll":
			list := editable
			if choice == "addpoll" {
				list = mine
			}
			var po Post
			if po, err = p.pickPost(ctx, s, list); err != nil {
				break
			}
			switch choice {
			case "edit":
				var body string
				if body, err = p.editor(ctx, s, "Edit post", po.Body); err == nil {
					err = p.Edit(ctx, s.UserID(), po.ID, body)
					show = true
				}
			case "delete":
				q := "Delete this post?"
				if po.ID == posts[0].ID {
					q = "This is the first post: deleting it deletes the whole thread. Continue?"
				}
				ok, cerr := tui.Confirm(ctx, s.UI(), s.Title(t.Title), q)
				if cerr != nil || !ok {
					err = cerr
					break
				}
				var gone bool
				if gone, err = p.DeletePost(ctx, s.UserID(), po.ID); err == nil && gone {
					return tui.Message(ctx, s.UI(), s.Title(c.Name), "Thread deleted.")
				}
			case "addpoll":
				if err = p.canAddPoll(ctx, s.UserID(), po.ID); err == nil {
					_, err = p.polls.CreateForm(ctx, s, pollContext(po.ID))
				}
			}
		case "chat":
			err = p.chat.Enter(ctx, s, t.ChatChannelID)
		case "enablechat":
			var cid int64
			if cid, err = p.EnableChat(ctx, s.UserID(), id); err == nil {
				err = p.chat.Enter(ctx, s, cid)
			}
		case "lock", "unlock":
			err = p.SetLocked(ctx, s.UserID(), id, choice == "lock")
		case "delthread":
			ok, cerr := tui.Confirm(ctx, s.UI(), s.Title(t.Title), "Delete this thread with all its posts, polls and chat?")
			if cerr != nil || !ok {
				err = cerr
				break
			}
			if err = p.DeleteThread(ctx, s.UserID(), id); err == nil {
				return tui.Message(ctx, s.UI(), s.Title(c.Name), "Thread deleted.")
			}
		}
		if err = report(ctx, s, err); err != nil {
			return err
		}
	}
}

func (p *Plugin) pickPost(ctx context.Context, s plugin.Session, posts []Post) (Post, error) {
	var items []tui.MenuItem
	for _, po := range posts {
		first := strings.SplitN(strings.TrimSpace(po.Body), "\n", 2)[0]
		if r := []rune(first); len(r) > 60 {
			first = string(r[:60]) + "..."
		}
		items = append(items, tui.MenuItem{Value: strconv.FormatInt(po.ID, 10),
			Label: fmt.Sprintf("%s, %s: %s", po.Author, po.CreatedAt.UTC().Format("2006-01-02 15:04"), first)})
	}
	choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Choose a post"), Items: items})
	if err != nil {
		return Post{}, err
	}
	for _, po := range posts {
		if strconv.FormatInt(po.ID, 10) == choice {
			return po, nil
		}
	}
	return Post{}, ErrNotFound
}

func (p *Plugin) choosePoll(ctx context.Context, s plugin.Session, posts []Post) error {
	var items []tui.MenuItem
	for i, po := range posts {
		for _, pid := range po.Polls {
			pl, err := p.polls.Get(ctx, s.UserID(), pid)
			if err != nil {
				return err
			}
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(pid, 10), Label: pl.Question, Help: fmt.Sprintf("On post %d by %s", i+1, po.Author)})
		}
	}
	choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Polls in this thread"), Items: items})
	if err != nil {
		return err
	}
	id, _ := strconv.ParseInt(choice, 10, 64)
	return p.polls.Run(ctx, s, id)
}
