package bbs

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/menu"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// ---- users -----------------------------------------------------------------

// findUser asks for a username prefix and lets the admin pick a match.
func (s *session) findUser(ctx context.Context, title string) (auth.User, error) {
	fm := &form.Form{Title: title, Fields: []form.Field{{
		Name: "q", Label: "Username starts with", Kind: form.SingleLine, MaxLen: 32,
		Help: "Leave empty to list everyone (up to " + strconv.Itoa(auth.MaxListUsers) + ").",
	}}}
	v, err := s.Form(ctx, fm, nil, nil)
	if err != nil {
		return auth.User{}, err
	}
	users, err := s.h.Auth.ListUsers(ctx, s.userID, v["q"])
	if err != nil {
		return auth.User{}, err
	}
	if len(users) == 0 {
		return auth.User{}, errors.Join(tui.ErrCancelled, tui.Message(ctx, s.ui, s.Title(title), "No users match."))
	}
	var items []tui.MenuItem
	for _, u := range users {
		items = append(items, tui.MenuItem{Value: strconv.FormatInt(u.ID, 10), Label: u.Username + " (" + u.Status + ")"})
	}
	choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title(title), Intro: fmt.Sprintf("%d match(es).", len(users)), Items: items})
	if err != nil {
		return auth.User{}, err
	}
	id, _ := strconv.ParseInt(choice, 10, 64)
	return s.h.Auth.UserByID(ctx, id)
}

func (s *session) adminUsers(ctx context.Context) error {
	u, err := s.findUser(ctx, "Users")
	if err != nil {
		return err
	}
	for {
		u, err = s.h.Auth.UserByID(ctx, u.ID)
		if err != nil {
			return err
		}
		groups, err := s.h.Perms.UserGroups(ctx, u.ID)
		if err != nil {
			return err
		}
		set, err := s.h.Perms.Permissions(ctx, s.userID)
		if err != nil {
			return err
		}
		gs := "none"
		if len(groups) > 0 {
			gs = strings.Join(groups, ", ")
		}
		intro := fmt.Sprintf("%s: status %s, groups %s, registered %s, last login %s.",
			u.Username, u.Status, gs, fmtTime(&u.CreatedAt), fmtTime(u.LastLoginAt))
		erasure, erasing, err := s.h.Privacy.Erasure(ctx, u.ID)
		if err != nil {
			return err
		}
		switch {
		case erasing && erasure.CompletedAt != nil:
			intro += " This account was erased on " + fmtTime(erasure.CompletedAt) + "."
		case erasing:
			intro += " The member asked for this account to be erased; it will be erased on " + fmtTime(&erasure.EraseAfter) + "."
		}
		var items []tui.MenuItem
		if set.Has(perm.UsersManage) && u.ID != s.userID {
			switch {
			case erasing && erasure.CompletedAt == nil:
				items = append(items, tui.MenuItem{Value: "cancelerase", Label: "Cancel the erasure request", Help: "Reactivates the account"})
			case erasing:
			case u.Status == auth.StatusActive:
				items = append(items, tui.MenuItem{Value: "lock", Label: "Lock account", Help: "The member cannot log in until unlocked"})
			case u.Status == auth.StatusLocked:
				items = append(items, tui.MenuItem{Value: "unlock", Label: "Unlock account"})
			}
			if !erasing || erasure.CompletedAt == nil {
				items = append(items, tui.MenuItem{Value: "email", Label: "Show email address", Help: "For account recovery. This is recorded in the audit log."})
			}
		}
		if set.Has(perm.GroupsManage) {
			items = append(items,
				tui.MenuItem{Value: "addgroup", Label: "Add to a group"},
				tui.MenuItem{Value: "rmgroup", Label: "Remove from a group"})
		}

		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("User " + u.Username), Intro: intro, Items: items})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "lock", "unlock":
			ok, cerr := tui.Confirm(ctx, s.ui, s.Title("User "+u.Username), choiceLabel(items, choice)+"?")
			if cerr != nil || !ok {
				err = cerr
				break
			}
			err = s.h.Auth.SetLocked(ctx, s.userID, u.ID, choice == "lock")
		case "cancelerase":
			ok, cerr := tui.Confirm(ctx, s.ui, s.Title("User "+u.Username), "Cancel the erasure and reactivate this account?")
			if cerr != nil || !ok {
				err = cerr
				break
			}
			err = s.h.Privacy.CancelErasure(ctx, s.userID, u.ID)
		case "email":
			var email string
			if email, err = s.h.Privacy.AdminEmail(ctx, s.userID, u.ID); err == nil {
				if email == "" {
					email = "none given"
				}
				err = tui.Message(ctx, s.ui, s.Title("User "+u.Username), "Email address: "+email, "This access has been recorded in the audit log.")
			}
		case "addgroup":
			err = s.pickGroup(ctx, "Add "+u.Username+" to", func(g perm.Group) bool { return !slices.Contains(groups, g.Name) },
				func(g perm.Group) error { return s.h.Perms.AddMember(ctx, s.userID, g.ID, u.ID) })
		case "rmgroup":
			err = s.pickGroup(ctx, "Remove "+u.Username+" from", func(g perm.Group) bool { return slices.Contains(groups, g.Name) },
				func(g perm.Group) error { return s.h.Perms.RemoveMember(ctx, s.userID, g.ID, u.ID) })
		}
		if msg := adminErrorMessage(err); msg != "" {
			err = tui.Message(ctx, s.ui, s.Title("User "+u.Username), msg)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func choiceLabel(items []tui.MenuItem, v string) string {
	for _, it := range items {
		if it.Value == v {
			return it.Label
		}
	}
	return v
}

// pickGroup lets the admin choose one of the groups matching keep, then
// applies do to it.
func (s *session) pickGroup(ctx context.Context, title string, keep func(perm.Group) bool, do func(perm.Group) error) error {
	groups, err := s.h.Perms.Groups(ctx)
	if err != nil {
		return err
	}
	byID := map[string]perm.Group{}
	var items []tui.MenuItem
	for _, g := range groups {
		if keep(g) {
			id := strconv.FormatInt(g.ID, 10)
			byID[id] = g
			items = append(items, tui.MenuItem{Value: id, Label: g.Name, Help: g.Description})
		}
	}
	if len(items) == 0 {
		return tui.Message(ctx, s.ui, s.Title(title), "There are no groups to choose from.")
	}
	choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title(title), Items: items})
	if err != nil {
		return err
	}
	return do(byID[choice])
}

// ---- groups ----------------------------------------------------------------

func (s *session) adminGroups(ctx context.Context) error {
	for {
		groups, err := s.h.Perms.Groups(ctx)
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		for _, g := range groups {
			help := fmt.Sprintf("%d permission(s)", len(g.Permissions))
			if g.Builtin {
				help += ", built in"
			}
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(g.ID, 10), Label: g.Name, Help: help})
		}
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Groups"), Items: items,
			Actions: []tui.Action{{Key: 'n', Value: "new", Label: "Create a group"}}})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		if choice == "new" {
			err = s.createGroup(ctx)
		} else {
			id, _ := strconv.ParseInt(choice, 10, 64)
			err = s.groupDetail(ctx, id)
		}
		if msg := adminErrorMessage(err); msg != "" {
			err = tui.Message(ctx, s.ui, s.Title("Groups"), msg)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func (s *session) createGroup(ctx context.Context) error {
	fm := &form.Form{Title: "Create a group", Fields: []form.Field{
		{Name: "name", Label: "Name", Kind: form.SingleLine, Required: true, MinLen: 2, MaxLen: 32,
			Help: "Lowercase letters, digits, '_' or '-', starting with a letter."},
		{Name: "desc", Label: "Description", Kind: form.SingleLine, MaxLen: 200},
	}}
	var errs form.Errors
	vals := form.Values{}
	for {
		v, err := s.Form(ctx, fm, vals, errs)
		if err != nil {
			return err
		}
		vals = v
		_, err = s.h.Perms.CreateGroup(ctx, s.userID, v["name"], v["desc"])
		switch {
		case errors.Is(err, perm.ErrInvalidGroup):
			errs = form.Errors{"name": err}
		case errors.Is(err, perm.ErrExists):
			errs = form.Errors{"name": errors.New("a group with that name already exists")}
		case err != nil:
			return err
		default:
			return tui.Message(ctx, s.ui, s.Title("Groups"), "Group created. Grant it permissions from its page.")
		}
	}
}

func (s *session) groupDetail(ctx context.Context, id int64) error {
	for {
		g, err := s.h.Perms.GroupByID(ctx, id)
		if err != nil {
			return err
		}
		members, err := s.h.Perms.GroupMembers(ctx, id)
		if err != nil {
			return err
		}
		perms := "none"
		if len(g.Permissions) > 0 {
			perms = strings.Join(g.Permissions, ", ")
		}
		intro := fmt.Sprintf("%s. Permissions: %s. Members: %d.", g.Description, perms, len(members))
		items := []tui.MenuItem{
			{Value: "members", Label: "List members"},
			{Value: "grant", Label: "Grant a permission"},
			{Value: "revoke", Label: "Revoke a permission"},
			{Value: "add", Label: "Add a member"},
			{Value: "remove", Label: "Remove a member"},
		}
		if !g.Builtin {
			items = append(items, tui.MenuItem{Value: "delete", Label: "Delete this group"})
		}
		title := "Group " + g.Name
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title(title), Intro: intro, Items: items})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "members":
			p := tui.Page{Title: s.Title(title + " members")}
			for _, m := range members {
				p.Lines = append(p.Lines, tui.Text(m.Username+" ("+m.Status+")"))
			}
			if len(members) == 0 {
				p.Lines = append(p.Lines, tui.Text("This group has no members."))
			}
			err = s.ui.Show(ctx, p)
		case "grant":
			var items []tui.MenuItem
			for _, pm := range s.h.Perms.Registry().All() {
				if !slices.Contains(g.Permissions, pm.Name) {
					items = append(items, tui.MenuItem{Value: pm.Name, Label: pm.Name, Help: pm.Description})
				}
			}
			var p string
			if p, err = s.ui.Choose(ctx, tui.Menu{Title: s.Title("Grant to " + g.Name), Items: items}); err == nil {
				err = s.h.Perms.Grant(ctx, s.userID, g.ID, p)
			}
		case "revoke":
			var items []tui.MenuItem
			for _, p := range g.Permissions {
				items = append(items, tui.MenuItem{Value: p, Label: p})
			}
			if len(items) == 0 {
				err = tui.Message(ctx, s.ui, s.Title(title), "This group has no permissions.")
				break
			}
			var p string
			if p, err = s.ui.Choose(ctx, tui.Menu{Title: s.Title("Revoke from " + g.Name), Items: items}); err == nil {
				err = s.h.Perms.Revoke(ctx, s.userID, g.ID, p)
			}
		case "add":
			var u auth.User
			if u, err = s.findUser(ctx, "Add to "+g.Name); err == nil {
				err = s.h.Perms.AddMember(ctx, s.userID, g.ID, u.ID)
			}
		case "remove":
			var items []tui.MenuItem
			for _, m := range members {
				items = append(items, tui.MenuItem{Value: strconv.FormatInt(m.UserID, 10), Label: m.Username})
			}
			if len(items) == 0 {
				err = tui.Message(ctx, s.ui, s.Title(title), "This group has no members.")
				break
			}
			var c string
			if c, err = s.ui.Choose(ctx, tui.Menu{Title: s.Title("Remove from " + g.Name), Items: items}); err == nil {
				uid, _ := strconv.ParseInt(c, 10, 64)
				err = s.h.Perms.RemoveMember(ctx, s.userID, g.ID, uid)
			}
		case "delete":
			ok, cerr := tui.Confirm(ctx, s.ui, s.Title(title), "Delete this group? Its members lose its permissions.")
			if cerr != nil || !ok {
				err = cerr
				break
			}
			if err = s.h.Perms.DeleteGroup(ctx, s.userID, g.ID); err == nil {
				return tui.Message(ctx, s.ui, s.Title("Groups"), "Group deleted.")
			}
		}
		if msg := adminErrorMessage(err); msg != "" {
			err = tui.Message(ctx, s.ui, s.Title(title), msg)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

// ---- plugin settings -------------------------------------------------------

func (s *session) pluginSettings(ctx context.Context) error {
	var items []tui.MenuItem
	if s.h.Plugins != nil {
		for _, p := range s.h.Plugins.Plugins() {
			if len(p.Settings.Defs()) > 0 {
				items = append(items, tui.MenuItem{Value: p.Manifest.ID, Label: p.Manifest.Name, Help: p.Manifest.Description})
			}
		}
	}
	if len(items) == 0 {
		return tui.Message(ctx, s.ui, s.Title("Plugin settings"), "No installed plugin has settings.")
	}
	choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Plugin settings"), Items: items})
	if err != nil {
		return err
	}
	for _, p := range s.h.Plugins.Plugins() {
		if p.Manifest.ID != choice {
			continue
		}
		vals, err := p.Settings.All(ctx)
		if err != nil {
			return err
		}
		var errs form.Errors
		for {
			v, err := s.Form(ctx, p.Settings.Form(p.Manifest.Name+" settings"), vals, errs)
			if err != nil {
				return err
			}
			vals = v
			if errs, err = p.Settings.Save(ctx, s.userID, v); err != nil {
				return err
			}
			if len(errs) == 0 {
				return tui.Message(ctx, s.ui, s.Title("Plugin settings"), "Settings saved.")
			}
		}
	}
	return nil
}

// ---- menu editor -----------------------------------------------------------

// targetOptions lists every menu item for the editor.
func (s *session) targetOptions() []form.Option {
	var out []form.Option
	for _, d := range s.h.MenuDefaults() {
		out = append(out, form.Option{Value: d.Target, Label: d.Label + " (" + d.Target + ")"})
	}
	return out
}

func (s *session) permissionOptions() []form.Option {
	out := []form.Option{{Value: "none", Label: "No extra permission"}}
	for _, p := range s.h.Perms.Registry().All() {
		out = append(out, form.Option{Value: p.Name, Label: p.Name + ": " + p.Description})
	}
	return out
}

func describeEntry(h *Handler, e menu.Entry) string {
	var d string
	if e.Kind == menu.KindSubmenu {
		d = "submenu"
	} else if h.itemExists(e.Target) {
		d = e.Target
	} else {
		d = e.Target + ", missing: hidden from members"
	}
	if e.Permission != "" {
		d += ", needs " + e.Permission
	}
	return d
}

func (s *session) menuEditor(ctx context.Context, parent int64, title string) error {
	for {
		entries, err := s.h.Menu.Children(ctx, parent)
		if err != nil {
			return err
		}
		byID := map[string]menu.Entry{}
		var items []tui.MenuItem
		for _, e := range entries {
			id := strconv.FormatInt(e.ID, 10)
			byID[id] = e
			items = append(items, tui.MenuItem{Value: id, Label: e.Label, Help: describeEntry(s.h, e)})
		}
		actions := []tui.Action{{Key: 'a', Value: "add", Label: "Add an entry"}}
		if parent == 0 {
			actions = append(actions, tui.Action{Key: 'r', Value: "reset", Label: "Reset to the default menu"})
		}
		choice, err := s.ui.Choose(ctx, tui.Menu{
			Title: s.Title("Menu editor: " + title), Intro: "Choose an entry to change it, or add one.", Items: items, Actions: actions,
		})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "add":
			err = s.addMenuEntry(ctx, parent)
		case "reset":
			ok, cerr := tui.Confirm(ctx, s.ui, s.Title("Menu editor"), "Discard all changes and restore the default menu?")
			if cerr != nil || !ok {
				err = cerr
				break
			}
			err = s.h.Menu.Reset(ctx, s.userID, s.h.MenuDefaults())
		default:
			err = s.editMenuEntry(ctx, byID[choice])
		}
		err = s.menuError(ctx, err)
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

// menuError shows expected menu errors as messages.
func (s *session) menuError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, menu.ErrProtected):
		return tui.Message(ctx, s.ui, s.Title("Menu editor"), "Administration and Log out cannot be deleted, so nobody is ever locked out. You can rename or move them.")
	case errors.Is(err, menu.ErrNotEmpty), errors.Is(err, menu.ErrInvalid):
		return tui.Message(ctx, s.ui, s.Title("Menu editor"), err.Error()+".")
	}
	if msg := adminErrorMessage(err); msg != "" {
		return tui.Message(ctx, s.ui, s.Title("Menu editor"), msg)
	}
	return err
}

func (s *session) addMenuEntry(ctx context.Context, parent int64) error {
	fm := &form.Form{
		Title: "Add a menu entry",
		Fields: []form.Field{
			{Name: "kind", Label: "Type", Kind: form.Choice, Required: true, Options: []form.Option{
				{Value: menu.KindItem, Label: "A menu item"}, {Value: menu.KindSubmenu, Label: "A submenu"},
			}},
			{Name: "target", Label: "Menu item", Kind: form.Choice, Options: s.targetOptions(), Help: "Only used for a menu item."},
			{Name: "label", Label: "Label", Kind: form.SingleLine, MaxLen: menu.MaxLabelLen,
				Help: "Required for a submenu. For a menu item, empty uses the item's own name."},
			{Name: "perm", Label: "Extra permission", Kind: form.Choice, Required: true, Options: s.permissionOptions(),
				Help: "Members also need this to see the entry."},
		},
		Check: func(v form.Values) map[string]error {
			switch {
			case v["kind"] == menu.KindItem && v["target"] == "":
				return map[string]error{"target": errors.New("choose the menu item")}
			case v["kind"] == menu.KindSubmenu && v["label"] == "":
				return map[string]error{"label": errors.New("a submenu needs a label")}
			}
			return nil
		},
	}
	v, err := s.Form(ctx, fm, form.Values{"kind": menu.KindItem, "perm": "none"}, nil)
	if err != nil {
		return err
	}
	e := menu.Entry{ParentID: parent, Kind: v["kind"], Target: v["target"], Label: v["label"]}
	if v["perm"] != "none" {
		e.Permission = v["perm"]
	}
	if e.Kind == menu.KindItem && e.Label == "" {
		info, _ := s.h.item(e.Target)
		e.Label = info.label
	}
	_, err = s.h.Menu.Add(ctx, s.userID, e, s.h.itemExists)
	return err
}

func (s *session) editMenuEntry(ctx context.Context, e menu.Entry) error {
	items := []tui.MenuItem{
		{Value: "edit", Label: "Rename or change permission"},
		{Value: "up", Label: "Move up"},
		{Value: "down", Label: "Move down"},
	}
	if e.Kind == menu.KindSubmenu {
		items = append(items, tui.MenuItem{Value: "open", Label: "Edit the entries in this submenu"})
	}
	items = append(items, tui.MenuItem{Value: "delete", Label: "Delete"})
	choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Menu entry: " + e.Label), Intro: describeEntry(s.h, e), Items: items})
	if err != nil {
		return err
	}
	switch choice {
	case "edit":
		fm := &form.Form{Title: "Menu entry", Fields: []form.Field{
			{Name: "label", Label: "Label", Kind: form.SingleLine, Required: true, MaxLen: menu.MaxLabelLen},
			{Name: "perm", Label: "Extra permission", Kind: form.Choice, Required: true, Options: s.permissionOptions()},
		}}
		p := e.Permission
		if p == "" {
			p = "none"
		}
		v, err := s.Form(ctx, fm, form.Values{"label": e.Label, "perm": p}, nil)
		if err != nil {
			return err
		}
		if v["perm"] == "none" {
			v["perm"] = ""
		}
		return s.h.Menu.Update(ctx, s.userID, e.ID, v["label"], v["perm"])
	case "up":
		return s.h.Menu.Move(ctx, s.userID, e.ID, -1)
	case "down":
		return s.h.Menu.Move(ctx, s.userID, e.ID, 1)
	case "open":
		return s.menuEditor(ctx, e.ID, e.Label)
	case "delete":
		ok, err := tui.Confirm(ctx, s.ui, s.Title("Menu editor"), "Delete \""+e.Label+"\" from the menu?")
		if err != nil || !ok {
			return err
		}
		return s.h.Menu.Delete(ctx, s.userID, e.ID)
	}
	return nil
}

// ---- audit log -------------------------------------------------------------

const auditPageSize = 200

func (s *session) auditLog(ctx context.Context) error {
	if err := s.h.Perms.Require(ctx, s.userID, perm.AuditView); err != nil {
		return err
	}
	recs, err := audit.Recent(ctx, s.h.Auth.DB(), auditPageSize)
	if err != nil {
		return err
	}
	p := tui.Page{Title: s.Title("Audit log")}
	p.Lines = append(p.Lines, tui.Text(fmt.Sprintf("The %d most recent entries, newest first.", len(recs))), tui.Text(""))
	for _, r := range recs {
		line := fmt.Sprintf("%s  %s  %s", r.At.UTC().Format("2006-01-02 15:04"), r.Actor, r.Action)
		if r.TargetType != "" {
			line += " " + r.TargetType
			if r.TargetID != "" {
				line += " " + r.TargetID
			}
		}
		if r.Detail != "" {
			line += ": " + r.Detail
		}
		p.Lines = append(p.Lines, tui.Text(line))
	}
	return s.ui.Show(ctx, p)
}
