package contacts

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// userMessage turns expected errors into a message; "" for others.
func userMessage(err error) string {
	switch {
	case errors.Is(err, ErrUnknownUser), errors.Is(err, ErrSelf), errors.Is(err, ErrExists),
		errors.Is(err, ErrLimit), errors.Is(err, ErrInvalid), errors.Is(err, ErrNotFound):
		return err.Error() + "."
	}
	return ""
}

func (p *Plugin) run(ctx context.Context, s plugin.Session) error {
	for {
		list, err := p.List(ctx, s.UserID())
		if err != nil {
			return err
		}
		friends := 0
		for _, c := range list {
			if c.Mutual {
				friends++
			}
		}
		choice, err := s.UI().Choose(ctx, tui.Menu{
			Title: s.Title("Contacts"),
			Intro: fmt.Sprintf("You have %d contact(s); %d of them have you as a contact too (friends).", len(list), friends),
			Items: []tui.MenuItem{
				{Value: "list", Label: "My contacts"},
				{Value: "add", Label: "Add a contact"},
				{Value: "groups", Label: "Contact groups", Help: "Named groups you can send messages to"},
				{Value: "back", Label: "Back"},
			},
		})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "list":
			err = p.browse(ctx, s, list)
		case "add":
			err = p.addForm(ctx, s)
		case "groups":
			err = p.groups(ctx, s)
		}
		if msg := userMessage(err); msg != "" {
			err = tui.Message(ctx, s.UI(), s.Title("Contacts"), msg)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func contactLabel(c Contact) string {
	if c.Mutual {
		return c.Username + " (friend)"
	}
	return c.Username
}

func (p *Plugin) browse(ctx context.Context, s plugin.Session, list []Contact) error {
	if len(list) == 0 {
		return tui.Message(ctx, s.UI(), s.Title("Contacts"), "You have no contacts yet. Choose Add a contact to add someone by username.")
	}
	var items []tui.MenuItem
	byID := map[string]Contact{}
	for _, c := range list {
		id := strconv.FormatInt(c.UserID, 10)
		byID[id] = c
		items = append(items, tui.MenuItem{Value: id, Label: contactLabel(c), Help: c.Note})
	}
	choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("My contacts"), Items: items})
	if err != nil {
		return err
	}
	c := byID[choice]
	friend := "No: they do not have you in their contacts."
	if c.Mutual {
		friend = "Yes: you are in each other's contacts."
	}
	note := c.Note
	if note == "" {
		note = "none"
	}
	action, err := s.UI().Choose(ctx, tui.Menu{
		Title: s.Title("Contact " + c.Username),
		Intro: fmt.Sprintf("Friend: %s Note: %s. Added %s.", friend, note, c.AddedAt.UTC().Format("2006-01-02")),
		Items: []tui.MenuItem{
			{Value: "note", Label: "Edit note", Help: "Private: only you see it"},
			{Value: "remove", Label: "Remove from contacts"},
			{Value: "back", Label: "Back"},
		},
	})
	if err != nil || action == "back" {
		return err
	}
	if action == "remove" {
		ok, err := tui.Confirm(ctx, s.UI(), s.Title("Contacts"), "Remove "+c.Username+" from your contacts and contact groups?")
		if err != nil || !ok {
			return err
		}
		return p.Remove(ctx, s.UserID(), c.UserID)
	}
	fm := &form.Form{Title: "Note for " + c.Username, Fields: []form.Field{
		{Name: "note", Label: "Note", Kind: form.SingleLine, MaxLen: MaxNoteLen},
	}}
	v, err := s.Form(ctx, fm, form.Values{"note": c.Note}, nil)
	if err != nil {
		return err
	}
	return p.SetNote(ctx, s.UserID(), c.UserID, v["note"])
}

func (p *Plugin) addForm(ctx context.Context, s plugin.Session) error {
	fm := &form.Form{Title: "Add a contact", Fields: []form.Field{
		{Name: "user", Label: "Username", Kind: form.SingleLine, Required: true, MaxLen: 32},
		{Name: "note", Label: "Note", Kind: form.SingleLine, MaxLen: MaxNoteLen, Help: "Optional and private: only you see it."},
	}}
	vals, errs := form.Values{}, form.Errors{}
	for {
		v, err := s.Form(ctx, fm, vals, errs)
		if err != nil {
			return err
		}
		vals = v
		err = p.Add(ctx, s.UserID(), v["user"], v["note"])
		switch {
		case err == nil:
			return tui.Message(ctx, s.UI(), s.Title("Contacts"), "Contact added.")
		case errors.Is(err, ErrUnknownUser), errors.Is(err, ErrSelf), errors.Is(err, ErrExists):
			errs = form.Errors{"user": err}
		default:
			return err
		}
	}
}

func (p *Plugin) groups(ctx context.Context, s plugin.Session) error {
	for {
		gs, err := p.Groups(ctx, s.UserID())
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		byID := map[string]Group{}
		for _, g := range gs {
			id := strconv.FormatInt(g.ID, 10)
			byID[id] = g
			items = append(items, tui.MenuItem{Value: id, Label: g.Name, Help: fmt.Sprintf("%d member(s)", g.Members)})
		}
		items = append(items, tui.MenuItem{Value: "new", Label: "Create a group"}, tui.MenuItem{Value: "back", Label: "Back"})
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Contact groups"), Items: items})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		if choice == "new" {
			fm := &form.Form{Title: "Create a contact group", Fields: []form.Field{
				{Name: "name", Label: "Group name", Kind: form.SingleLine, Required: true, MaxLen: MaxGroupName},
			}}
			var v form.Values
			if v, err = s.Form(ctx, fm, nil, nil); err == nil {
				_, err = p.CreateGroup(ctx, s.UserID(), v["name"])
			}
		} else {
			err = p.group(ctx, s, byID[choice])
		}
		if msg := userMessage(err); msg != "" {
			err = tui.Message(ctx, s.UI(), s.Title("Contact groups"), msg)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func (p *Plugin) group(ctx context.Context, s plugin.Session, g Group) error {
	members, err := p.GroupMembers(ctx, s.UserID(), g.ID)
	if err != nil {
		return err
	}
	action, err := s.UI().Choose(ctx, tui.Menu{
		Title: s.Title("Group " + g.Name), Intro: fmt.Sprintf("%d member(s).", len(members)),
		Items: []tui.MenuItem{
			{Value: "list", Label: "List members"},
			{Value: "add", Label: "Add a contact to this group"},
			{Value: "remove", Label: "Remove a member"},
			{Value: "delete", Label: "Delete this group", Help: "Your contacts are kept"},
			{Value: "back", Label: "Back"},
		},
	})
	if err != nil || action == "back" {
		return err
	}
	pick := func(title string, from []Contact) (int64, error) {
		if len(from) == 0 {
			return 0, errors.Join(tui.ErrCancelled, tui.Message(ctx, s.UI(), s.Title(title), "There is nobody to choose."))
		}
		var items []tui.MenuItem
		for _, c := range from {
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(c.UserID, 10), Label: contactLabel(c)})
		}
		v, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title(title), Items: items})
		if err != nil {
			return 0, err
		}
		return strconv.ParseInt(v, 10, 64)
	}
	switch action {
	case "list":
		pg := tui.Page{Title: s.Title("Group " + g.Name)}
		for _, c := range members {
			pg.Lines = append(pg.Lines, tui.Text(contactLabel(c)))
		}
		if len(members) == 0 {
			pg.Lines = append(pg.Lines, tui.Text("This group is empty."))
		}
		return s.UI().Show(ctx, pg)
	case "add":
		all, err := p.List(ctx, s.UserID())
		if err != nil {
			return err
		}
		var outside []Contact
		for _, c := range all {
			if !containsUser(members, c.UserID) {
				outside = append(outside, c)
			}
		}
		id, err := pick("Add to "+g.Name, outside)
		if err != nil {
			return err
		}
		return p.AddToGroup(ctx, s.UserID(), g.ID, id)
	case "remove":
		id, err := pick("Remove from "+g.Name, members)
		if err != nil {
			return err
		}
		return p.RemoveFromGroup(ctx, s.UserID(), g.ID, id)
	case "delete":
		ok, err := tui.Confirm(ctx, s.UI(), s.Title("Contact groups"), "Delete the group "+g.Name+"? Your contacts are kept.")
		if err != nil || !ok {
			return err
		}
		return p.DeleteGroup(ctx, s.UserID(), g.ID)
	}
	return nil
}

func containsUser(list []Contact, id int64) bool {
	for _, c := range list {
		if c.UserID == id {
			return true
		}
	}
	return false
}
