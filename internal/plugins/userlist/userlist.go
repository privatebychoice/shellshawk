// Package userlist is the core User List plugin (docs/DESIGN.md §12): browse
// and search members, see which friends are online, list your contacts and
// contact groups, and open a member's profile.
//
// Until the privacy settings exist (stage 9) it shows only what is public by
// design — usernames and join dates — and shows online status only for
// friends (mutual contacts).
package userlist

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/contacts"
	"go.privatebychoice.com/shellshawk/internal/plugins/messages"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

const pageSize = 25

// Plugin implements plugin.Plugin.
type Plugin struct {
	h        *plugin.Host
	contacts *contacts.Plugin
	messages *messages.Plugin // optional
}

// New returns the User List plugin. msgs may be nil.
func New(c *contacts.Plugin, msgs *messages.Plugin) *Plugin {
	return &Plugin{contacts: c, messages: msgs}
}

var _ plugin.Plugin = (*Plugin)(nil)

// Manifest implements plugin.Plugin.
func (p *Plugin) Manifest() plugin.Manifest {
	return plugin.Manifest{
		ID: "userlist", Name: "Members", Version: "1.0.0",
		Description: "Member listings and profiles",
		MenuItems:   []plugin.MenuItem{{Key: "main", Label: "Members", Help: "Browse members and see which friends are online", Run: p.run}},
	}
}

// Init implements plugin.Plugin.
func (p *Plugin) Init(_ context.Context, h *plugin.Host) error {
	p.h = h
	return nil
}

// relation describes how the viewer relates to another member.
type relation struct {
	self, contact, friend, online bool
}

func (p *Plugin) relate(ctx context.Context, viewer, other int64) (relation, error) {
	r := relation{self: viewer == other}
	var err error
	if r.contact, err = p.contacts.IsContact(ctx, viewer, other); err != nil {
		return r, err
	}
	if r.friend, err = p.contacts.IsFriend(ctx, viewer, other); err != nil {
		return r, err
	}
	// Online status is shown only between friends until members can choose
	// who sees it.
	r.online = r.friend && p.h.Presence != nil && p.h.Presence.IsOnline(other)
	return r, nil
}

func (r relation) tag() string {
	switch {
	case r.self:
		return " (you)"
	case r.friend && r.online:
		return " (friend, online)"
	case r.friend:
		return " (friend)"
	case r.contact:
		return " (contact)"
	}
	return ""
}

func (p *Plugin) run(ctx context.Context, s plugin.Session) error {
	for {
		online, err := p.onlineFriends(ctx, s.UserID())
		if err != nil {
			return err
		}
		_, total, err := p.h.Auth.Members(ctx, "", 0, 1)
		if err != nil {
			return err
		}
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Members"), Items: []tui.MenuItem{
			{Value: "all", Label: fmt.Sprintf("All members (%d)", total), Help: "Browse or search by username"},
			{Value: "online", Label: fmt.Sprintf("Friends online now (%d)", len(online)), Help: "Friends are members who have you as a contact too"},
			{Value: "contacts", Label: "My contacts"},
			{Value: "group", Label: "A contact group"},
			{Value: "back", Label: "Back"},
		}})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "all":
			err = p.browse(ctx, s)
		case "online":
			err = p.pickFrom(ctx, s, "Friends online now", online, "None of your friends are online.")
		case "contacts":
			var list []contacts.Contact
			if list, err = p.contacts.List(ctx, s.UserID()); err == nil {
				err = p.pickFrom(ctx, s, "My contacts", list, "You have no contacts.")
			}
		case "group":
			err = p.groupMembers(ctx, s)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

// onlineFriends returns the viewer's friends who have a session open.
func (p *Plugin) onlineFriends(ctx context.Context, viewer int64) ([]contacts.Contact, error) {
	if p.h.Presence == nil {
		return nil, nil
	}
	list, err := p.contacts.List(ctx, viewer)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(list, func(c contacts.Contact) bool { return !c.Mutual || !p.h.Presence.IsOnline(c.UserID) }), nil
}

func (p *Plugin) pickFrom(ctx context.Context, s plugin.Session, title string, list []contacts.Contact, empty string) error {
	if len(list) == 0 {
		return tui.Message(ctx, s.UI(), s.Title(title), empty)
	}
	var items []tui.MenuItem
	for _, c := range list {
		r, err := p.relate(ctx, s.UserID(), c.UserID)
		if err != nil {
			return err
		}
		items = append(items, tui.MenuItem{Value: strconv.FormatInt(c.UserID, 10), Label: c.Username + r.tag(), Help: c.Note})
	}
	choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title(title), Items: items})
	if err != nil {
		return err
	}
	id, _ := strconv.ParseInt(choice, 10, 64)
	return p.profile(ctx, s, id)
}

func (p *Plugin) groupMembers(ctx context.Context, s plugin.Session) error {
	gs, err := p.contacts.Groups(ctx, s.UserID())
	if err != nil {
		return err
	}
	if len(gs) == 0 {
		return tui.Message(ctx, s.UI(), s.Title("Contact groups"), "You have no contact groups. Create them under Contacts.")
	}
	var items []tui.MenuItem
	for _, g := range gs {
		items = append(items, tui.MenuItem{Value: strconv.FormatInt(g.ID, 10), Label: fmt.Sprintf("%s (%d)", g.Name, g.Members)})
	}
	choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Contact groups"), Items: items})
	if err != nil {
		return err
	}
	id, _ := strconv.ParseInt(choice, 10, 64)
	members, err := p.contacts.GroupMembers(ctx, s.UserID(), id)
	if err != nil {
		return err
	}
	return p.pickFrom(ctx, s, "Group members", members, "This group is empty.")
}

// browse pages through all members, optionally filtered by a prefix.
func (p *Plugin) browse(ctx context.Context, s plugin.Session) error {
	fm := &form.Form{Title: "Find members", Fields: []form.Field{{
		Name: "q", Label: "Username starts with", Kind: form.SingleLine, MaxLen: 32, Help: "Leave empty to list everyone.",
	}}}
	v, err := s.Form(ctx, fm, nil, nil)
	if err != nil {
		return err
	}
	offset := 0
	for {
		list, total, err := p.h.Auth.Members(ctx, v["q"], offset, pageSize)
		if err != nil {
			return err
		}
		if total == 0 {
			return tui.Message(ctx, s.UI(), s.Title("Members"), "No members match.")
		}
		var items []tui.MenuItem
		if offset > 0 {
			items = append(items, tui.MenuItem{Value: "prev", Label: "Previous page"})
		}
		for _, m := range list {
			r, err := p.relate(ctx, s.UserID(), m.ID)
			if err != nil {
				return err
			}
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(m.ID, 10), Label: m.Username + r.tag(),
				Help: "Member since " + m.Since.UTC().Format("2006-01-02")})
		}
		if offset+len(list) < total {
			items = append(items, tui.MenuItem{Value: "next", Label: "Next page"})
		}
		intro := fmt.Sprintf("Members %d to %d of %d.", offset+1, offset+len(list), total)
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Members"), Intro: intro, Items: items})
		if err != nil {
			return err
		}
		switch choice {
		case "prev":
			offset = max(0, offset-pageSize)
		case "next":
			offset += pageSize
		default:
			id, _ := strconv.ParseInt(choice, 10, 64)
			if err := p.profile(ctx, s, id); err != nil && !errors.Is(err, tui.ErrCancelled) {
				return err
			}
		}
	}
}

// profile shows a member's public profile and what the viewer can do.
func (p *Plugin) profile(ctx context.Context, s plugin.Session, id int64) error {
	for {
		u, err := p.h.Auth.UserByID(ctx, id)
		if err != nil || u.Status != auth.StatusActive {
			return tui.Message(ctx, s.UI(), s.Title("Member"), "This member is not available.")
		}
		r, err := p.relate(ctx, s.UserID(), id)
		if err != nil {
			return err
		}
		var facts []string
		facts = append(facts, "Member since "+u.CreatedAt.UTC().Format("2006-01-02")+".")
		switch {
		case r.self:
			facts = append(facts, "This is you.")
		case r.friend:
			facts = append(facts, "Friend: you are in each other's contacts.")
			if r.online {
				facts = append(facts, "Online now.")
			}
		case r.contact:
			facts = append(facts, "In your contacts. They have not added you.")
		}
		var items []tui.MenuItem
		if !r.self && !r.contact {
			items = append(items, tui.MenuItem{Value: "add", Label: "Add to my contacts"})
		}
		if !r.self && p.messages != nil && p.messages.CanSend(ctx, s.UserID()) {
			items = append(items, tui.MenuItem{Value: "msg", Label: "Send a message"})
		}
		items = append(items, tui.MenuItem{Value: "back", Label: "Back"})
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title(u.Username), Intro: strings.Join(facts, " "), Items: items})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "add":
			if err := p.contacts.Add(ctx, s.UserID(), u.Username, ""); err != nil {
				return err
			}
		case "msg":
			if err := p.messages.Compose(ctx, s, u.Username); err != nil && !errors.Is(err, tui.ErrCancelled) {
				return err
			}
		}
	}
}
