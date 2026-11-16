package bbs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"

	"go.privatebychoice.com/shellshawk/internal/menu"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// errLogout unwinds nested menus when the member chooses Log out.
var errLogout = errors.New("log out")

// adminPermissions: holding any of these shows the Administration item.
var adminPermissions = []string{
	perm.UsersApprove, perm.UsersManage, perm.GroupsManage, perm.InviteCreate, perm.InviteManage,
	perm.SettingsManage, perm.PluginSettings, perm.MenuManage, perm.AuditView,
}

// coreItem is a menu item provided by the BBS itself.
type coreItem struct {
	key, label, help string
	anyOf            []string
	run              func(s *session, ctx context.Context) error
	// enabled, if set, hides the item when it returns false (e.g. the web
	// login code when the web interface is off).
	enabled func(h *Handler) bool
}

// coreItems returns the core items in default menu order. It is a function,
// not a variable, because the items' handlers refer back to the menu.
func coreItems() []coreItem {
	return []coreItem{
		{key: "settings", label: "Display settings", help: "Terminal type, colour theme and accessibility", run: (*session).settings},
		{key: "privacy", label: "Privacy and profile", help: "Your profile, who can see it, your data, erasing your account", run: (*session).privacyMenu},
		{key: "keys", label: "SSH keys", help: "Add or remove the keys you log in with", run: (*session).keys},
		{key: "termtest", label: "Terminal test", help: "Check which text styles your terminal can show", run: (*session).termTest},
		{key: "markdown", label: "Markdown guide", help: "How to format posts and messages, with a preview", run: (*session).markdownGuide},
		{key: "weblogin", label: "Web login code", help: "A one-time code to log in to the website", run: (*session).webLoginCode,
			enabled: func(h *Handler) bool { return h.WebLogin != nil }},
		{key: "admin", label: "Administration", help: "Users, groups, approvals, invites and system settings", anyOf: adminPermissions, run: (*session).admin},
		{key: "logout", label: "Log out", run: func(*session, context.Context) error { return errLogout }},
	}
}

func coreItemFor(target string) (coreItem, bool) {
	for _, c := range coreItems() {
		if "core:"+c.key == target {
			return c, true
		}
	}
	return coreItem{}, false
}

// MenuDefaults lists every menu item for the main menu's first-run layout:
// core items, then plugin items.
func (h *Handler) MenuDefaults() []menu.Default {
	var out []menu.Default
	for _, c := range coreItems() {
		out = append(out, menu.Default{Target: "core:" + c.key, Label: c.label})
	}
	if h.Plugins != nil {
		for _, it := range h.Plugins.Items() {
			out = append(out, menu.Default{Target: it.Target, Label: it.Label})
		}
	}
	return out
}

// itemInfo describes a target for menus and the menu editor.
type itemInfo struct {
	label, help string
	allowed     func(perm.Set) bool
	plugin      string // owning plugin, "" for core
}

func (h *Handler) item(target string) (itemInfo, bool) {
	if c, ok := coreItemFor(target); ok {
		mi := plugin.MenuItem{AnyOf: c.anyOf}
		allowed := mi.Allowed
		if c.enabled != nil && !c.enabled(h) {
			allowed = func(perm.Set) bool { return false }
		}
		return itemInfo{label: c.label, help: c.help, allowed: allowed}, true
	}
	if h.Plugins != nil {
		if it, ok := h.Plugins.Item(target); ok {
			return itemInfo{label: it.Label, help: it.Help, allowed: it.Allowed, plugin: it.PluginID}, true
		}
	}
	return itemInfo{}, false
}

func (h *Handler) itemExists(target string) bool {
	_, ok := h.item(target)
	return ok
}

// visible reports whether a member with set should see entry e. Submenus
// are shown only if something inside them is visible.
func (s *session) visible(ctx context.Context, e menu.Entry, set perm.Set, depth int) bool {
	if e.Permission != "" && !set.Has(e.Permission) {
		return false
	}
	if e.Kind == menu.KindItem {
		info, ok := s.h.item(e.Target)
		return ok && info.allowed(set) // items of removed plugins are hidden
	}
	if depth > 8 {
		return false
	}
	kids, err := s.h.Menu.Children(ctx, e.ID)
	if err != nil {
		s.log.Error("load submenu", "entry", e.ID, "err", err)
		return false
	}
	for _, k := range kids {
		if s.visible(ctx, k, set, depth+1) {
			return true
		}
	}
	return false
}

// home runs the member menu until the member logs out.
func (s *session) home(ctx context.Context) error {
	err := s.menuLoop(ctx, 0, "Main menu")
	if errors.Is(err, errLogout) {
		return nil
	}
	return err
}

func (s *session) menuLoop(ctx context.Context, parent int64, title string) error {
	for {
		set, err := s.h.Perms.Permissions(ctx, s.userID)
		if err != nil {
			return err
		}
		entries, err := s.h.Menu.Children(ctx, parent)
		if err != nil {
			return err
		}
		byID := map[string]menu.Entry{}
		var items []tui.MenuItem
		for _, e := range entries {
			if !s.visible(ctx, e, set, 0) {
				continue
			}
			id := strconv.FormatInt(e.ID, 10)
			byID[id] = e
			help := ""
			if info, ok := s.h.item(e.Target); ok {
				help = info.help
			}
			items = append(items, tui.MenuItem{Value: id, Label: e.Label, Help: help})
		}
		intro := ""
		if parent == 0 {
			u, err := s.h.Auth.UserByID(ctx, s.userID)
			if err != nil {
				return err
			}
			intro = "Welcome, " + u.Username + "."
		} else {
			items = append(items, tui.MenuItem{Value: "back", Label: "Back"})
		}
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title(title), Intro: intro, Items: items})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			if parent == 0 {
				return errLogout
			}
			return nil
		}
		if err != nil {
			return err
		}
		e := byID[choice]
		if e.Kind == menu.KindSubmenu {
			err = s.menuLoop(ctx, e.ID, e.Label)
		} else {
			err = s.runItem(ctx, e.Target)
		}
		if err != nil {
			return err
		}
	}
}

// sessionEnded reports errors that mean the connection is gone.
func sessionEnded(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// runItem runs a core or plugin menu item. Plugin failures (errors or
// panics) are logged and reported to the member without ending the session.
func (s *session) runItem(ctx context.Context, target string) error {
	if c, ok := coreItemFor(target); ok {
		err := c.run(s, ctx)
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		return err
	}
	it, ok := s.h.Plugins.Item(target)
	if !ok {
		return tui.Message(ctx, s.ui, s.Title("Unavailable"), "This item is no longer available.")
	}
	ps := &pluginSession{session: s, log: s.log.With("plugin", it.PluginID, "item", it.Key)}
	err := safeRun(func() error { return it.Run(ctx, ps) })
	switch {
	case err == nil, errors.Is(err, tui.ErrCancelled):
		return nil
	case sessionEnded(err):
		return err
	}
	ps.log.Error("plugin menu item failed", "err", err)
	return tui.Message(ctx, s.ui, s.Title("Error"), "Sorry, something went wrong. The problem has been logged.")
}

func safeRun(f func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return f()
}

// pluginSession is the session as seen by a plugin.
type pluginSession struct {
	*session
	log *slog.Logger
}

var _ plugin.Session = (*pluginSession)(nil)

func (p *pluginSession) UI() tui.UI        { return p.ui }
func (p *pluginSession) UserID() int64     { return p.userID }
func (p *pluginSession) Log() *slog.Logger { return p.log }
func (p *pluginSession) Permissions(ctx context.Context) (perm.Set, error) {
	return p.h.Perms.Permissions(ctx, p.userID)
}
