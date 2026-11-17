// Package userlist is the core User List plugin (docs/DESIGN.md §12): browse
// and search members, see which friends are online, list your contacts and
// contact groups, and open a member's profile.
//
// Profile fields and online status are shown only as each member's privacy
// settings allow (docs/DESIGN.md §5.1).
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
	"go.privatebychoice.com/shellshawk/internal/privacy"
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
	if p.h.Presence != nil && p.h.Presence.IsOnline(other) {
		r.online, err = p.maySeeOnline(ctx, viewer, other)
	}
	return r, err
}

// maySeeOnline applies other's "who can see that I am online" setting. With
// no privacy service, only friends see it.
func (p *Plugin) maySeeOnline(ctx context.Context, viewer, other int64) (bool, error) {
	if p.h.Privacy != nil {
		return p.h.Privacy.Allows(ctx, viewer, other, privacy.Online)
	}
	return p.contacts.IsFriend(ctx, viewer, other)
}

func (r relation) tag() string {
	var parts []string
	switch {
	case r.self:
		return " (you)"
	case r.friend:
		parts = append(parts, "friend")
	case r.contact:
		parts = append(parts, "contact")
	}
	if r.online {
		parts = append(parts, "online")
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func (p *Plugin) run(ctx context.Context, s plugin.Session) error {
	for {
		online, err := p.online(ctx, s.UserID())
		if err != nil {
			return err
		}
		_, total, err := p.h.Auth.Members(ctx, "", 0, 1)
		if err != nil {
			return err
		}
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Members"), Items: []tui.MenuItem{
			{Value: "all", Label: fmt.Sprintf("All members (%d)", total), Help: "Browse or search by username"},
			{Value: "online", Label: fmt.Sprintf("Online now (%d)", len(online)), Help: "Members who let you see that they are online"},
			{Value: "contacts", Label: "My contacts"},
			{Value: "group", Label: "A contact group"},
		}})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "all":
			err = p.browse(ctx, s)
		case "online":
			err = p.pickFrom(ctx, s, "Online now", online, "Nobody you can see is online.")
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

// online returns the members with a session open whose settings let the
// viewer see that, sorted by username.
func (p *Plugin) online(ctx context.Context, viewer int64) ([]contacts.Contact, error) {
	if p.h.Presence == nil {
		return nil, nil
	}
	var ids []int64
	for id := range p.h.Presence.Online() {
		if id == viewer {
			continue
		}
		ok, err := p.maySeeOnline(ctx, viewer, id)
		if err != nil {
			return nil, err
		}
		if ok {
			ids = append(ids, id)
		}
	}
	names, err := p.h.Auth.Usernames(ctx, ids)
	if err != nil {
		return nil, err
	}
	var out []contacts.Contact
	for _, id := range ids {
		if n, ok := names[id]; ok {
			out = append(out, contacts.Contact{UserID: id, Username: n})
		}
	}
	slices.SortFunc(out, func(a, b contacts.Contact) int { return strings.Compare(a.Username, b.Username) })
	return out, nil
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
		var actions []tui.Action
		if offset > 0 {
			actions = append(actions, tui.Action{Key: 'p', Value: "prev", Label: "Previous page"})
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
			actions = append(actions, tui.Action{Key: 'n', Value: "next", Label: "Next page"})
		}
		intro := fmt.Sprintf("Members %d to %d of %d.", offset+1, offset+len(list), total)
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Members"), Intro: intro, Items: items, Actions: actions})
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
		case r.contact:
			facts = append(facts, "In your contacts. They have not added you.")
		}
		if r.online && !r.self {
			facts = append(facts, "Online now.")
		}
		if p.h.Privacy != nil {
			v, err := p.h.Privacy.View(ctx, s.UserID(), id)
			if err != nil {
				return err
			}
			for _, f := range []struct{ label, value string }{
				{"Name", v.FullName}, {"Status", v.Status}, {"Email", v.Email}, {"Phone", v.Phone},
			} {
				if f.value != "" {
					facts = append(facts, f.label+": "+f.value+".")
				}
			}
			if v.LastLogin != nil {
				facts = append(facts, "Last login "+v.LastLogin.UTC().Format("2006-01-02 15:04 UTC")+".")
			}
		}
		var items []tui.MenuItem
		if !r.self && !r.contact {
			items = append(items, tui.MenuItem{Value: "add", Label: "Add to my contacts"})
		}
		if !r.self && p.messages != nil && p.messages.CanSend(ctx, s.UserID()) {
			items = append(items, tui.MenuItem{Value: "msg", Label: "Send a message"})
		}
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title(u.Username), Intro: strings.Join(facts, " "), Items: items})
		if errors.Is(err, tui.ErrCancelled) {
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
