package web

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"go.privatebychoice.com/shellshawk/internal/menu"
	"go.privatebychoice.com/shellshawk/internal/perm"
)

// The web navigation follows the member menu (docs/DESIGN.md §3.2): the
// top bar lists the main menu's entries, in the administrators' order and
// with their labels, and each submenu is a page of its own (/menu/{id}),
// as over SSH. Only entries that can be opened on the web are shown:
// Notifications, Administration (a page of the staff pages the member may
// use) and plugin items with a WebPath. A submenu with nothing for the web
// in it is left out, and an entry's extra permission hides it here too.

// maxMenuDepth bounds submenu nesting, as over SSH.
const maxMenuDepth = 8

// navState is what deciding visibility needs, worked out once per page.
type navState struct {
	set   perm.Set
	admin []navItem // the Administration page's links
	fresh int       // new notifications
}

func (s *Server) newNavState(ctx context.Context, user int64) (*navState, error) {
	set, err := s.cfg.Perms.Permissions(ctx, user)
	if err != nil {
		return nil, err
	}
	return &navState{set: set, admin: s.adminLinks(set), fresh: s.newNotifications(ctx, user)}, nil
}

// nav lists the main menu's entries the member can open on the web.
func (s *Server) nav(ctx context.Context, user int64) []navItem {
	ns, err := s.newNavState(ctx, user)
	if err != nil {
		LoggerFrom(ctx).Error("navigation: permissions", "err", err)
		return nil
	}
	links, err := s.menuLinks(ctx, 0, ns)
	if err != nil {
		LoggerFrom(ctx).Error("navigation: menu", "err", err)
	}
	return links
}

// adminLinks lists the staff pages a member with set may use.
func (s *Server) adminLinks(set perm.Set) []navItem {
	var out []navItem
	add := func(ok bool, label, href string) {
		if ok {
			out = append(out, navItem{Label: label, Href: href})
		}
	}
	add(set.Has(perm.UsersManage) || set.Has(perm.GroupsManage), "Users", "/admin/users")
	add(set.Has(perm.GroupsManage), "Groups", "/admin/groups")
	add(set.Has(perm.UsersApprove), "Approvals", "/admin/pending")
	add(set.Has(perm.InviteCreate) || set.Has(perm.InviteManage), "Invites", "/admin/invites")
	add(s.cfg.Connections != nil && set.Has(perm.SessionsManage), "Who is online", "/admin/online")
	add(set.Has(perm.AuditView), "Audit log", "/admin/audit")
	add(s.menuEnabled() && set.Has(perm.MenuManage), "Menu editor", "/admin/menu")
	add(s.transitionsEnabled() && set.Has(perm.TransitionsManage), "Transitions", "/admin/transitions")
	add(len(s.configurable()) > 0 && set.Has(perm.PluginSettings), "Plugin settings", "/admin/plugins")
	add(s.cfg.Settings != nil && set.Has(perm.SettingsManage), "Connection limits", "/admin/limits")
	add(s.cfg.Settings != nil && set.Has(perm.SettingsManage), "Branding", "/admin/branding")
	return out
}

func submenuPath(id int64) string { return "/menu/" + strconv.FormatInt(id, 10) }

// itemHref returns where a menu item opens on the web, or "" if it has no
// web page or the member may not use it. Items of removed plugins have
// none.
func (s *Server) itemHref(target string, ns *navState) string {
	switch target {
	case menu.TargetNotifications:
		if s.cfg.Notify != nil {
			return "/notifications"
		}
	case menu.TargetAdmin:
		if len(ns.admin) > 0 {
			return "/admin"
		}
	default:
		if s.cfg.Plugins == nil {
			return ""
		}
		if it, ok := s.cfg.Plugins.Item(target); ok && it.WebPath != "" && it.Allowed(ns.set) {
			return "/p/" + it.PluginID + it.WebPath
		}
	}
	return ""
}

// entryHref returns where entry e opens on the web, or "" if the member
// should not see it there: its extra permission is missing, its item has
// no web page, or (for a submenu) nothing inside it would be shown.
func (s *Server) entryHref(ctx context.Context, e menu.Entry, ns *navState, depth int) string {
	if e.Permission != "" && !ns.set.Has(e.Permission) {
		return ""
	}
	if e.Kind == menu.KindItem {
		return s.itemHref(e.Target, ns)
	}
	if depth > maxMenuDepth || s.cfg.Menu == nil {
		return ""
	}
	kids, err := s.cfg.Menu.Children(ctx, e.ID)
	if err != nil {
		LoggerFrom(ctx).Error("navigation: submenu", "entry", e.ID, "err", err)
		return ""
	}
	for _, k := range kids {
		if s.entryHref(ctx, k, ns, depth+1) != "" {
			return submenuPath(e.ID)
		}
	}
	return ""
}

// menuLinks lists the entries of a submenu (0 = the main menu) the member
// can open on the web. Without a menu service the main menu is
// Notifications, the plugins' items, then Administration.
func (s *Server) menuLinks(ctx context.Context, parent int64, ns *navState) ([]navItem, error) {
	var entries []menu.Entry
	if s.cfg.Menu != nil {
		var err error
		if entries, err = s.cfg.Menu.Children(ctx, parent); err != nil {
			return nil, err
		}
	} else if parent == 0 {
		entries = s.defaultEntries()
	}
	var out []navItem
	for _, e := range entries {
		href := s.entryHref(ctx, e, ns, 0)
		if href == "" {
			continue
		}
		label := e.Label
		if e.Target == menu.TargetNotifications {
			label = notificationsLabelFor(label, ns.fresh)
		}
		out = append(out, navItem{Label: label, Href: href})
	}
	return out, nil
}

func (s *Server) defaultEntries() []menu.Entry {
	out := []menu.Entry{{Kind: menu.KindItem, Target: menu.TargetNotifications, Label: "Notifications"}}
	if s.cfg.Plugins != nil {
		for _, it := range s.cfg.Plugins.Items() {
			out = append(out, menu.Entry{Kind: menu.KindItem, Target: it.Target, Label: it.Label})
		}
	}
	return append(out, menu.Entry{Kind: menu.KindItem, Target: menu.TargetAdmin, Label: "Administration"})
}

// errMenuHidden: the submenu does not exist or the member may not see it.
var errMenuHidden = errors.New("submenu not visible")

// visibleSubmenu loads submenu id if the member may see it on the web: it
// and every submenu above it pass their extra permissions, and something
// inside it can be opened on the web.
func (s *Server) visibleSubmenu(ctx context.Context, id int64, ns *navState) (menu.Entry, error) {
	e, err := s.cfg.Menu.Get(ctx, id)
	if errors.Is(err, menu.ErrNotFound) || (err == nil && e.Kind != menu.KindSubmenu) {
		return menu.Entry{}, errMenuHidden
	}
	if err != nil {
		return menu.Entry{}, err
	}
	if s.entryHref(ctx, e, ns, 0) == "" {
		return menu.Entry{}, errMenuHidden
	}
	for up, depth := e.ParentID, 0; up != 0; depth++ {
		p, err := s.cfg.Menu.Get(ctx, up)
		if err != nil || depth > maxMenuDepth {
			return menu.Entry{}, errMenuHidden
		}
		if p.Permission != "" && !ns.set.Has(p.Permission) {
			return menu.Entry{}, errMenuHidden
		}
		up = p.ParentID
	}
	return e, nil
}

// handleSubmenu shows a submenu's entries, like opening it over SSH.
func (s *Server) handleSubmenu(w http.ResponseWriter, r *http.Request) {
	sess := s.member(w, r)
	if sess == nil {
		return
	}
	ctx := r.Context()
	fail := func(err error) {
		LoggerFrom(ctx).Error("submenu page", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "The menu could not be read. Please try again.")
	}
	ns, err := s.newNavState(ctx, sess.UserID)
	if err != nil {
		fail(err)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var e menu.Entry
	if err == nil {
		e, err = s.visibleSubmenu(ctx, id, ns)
	}
	switch {
	case errors.Is(err, errMenuHidden) || errors.Is(err, strconv.ErrSyntax) || errors.Is(err, strconv.ErrRange):
		s.renderError(w, r, http.StatusNotFound, "That menu does not exist.")
		return
	case err != nil:
		fail(err)
		return
	}
	links, err := s.menuLinks(ctx, e.ID, ns)
	if err != nil {
		fail(err)
		return
	}
	backLabel, backHref := "Home", "/home"
	if e.ParentID != 0 {
		if p, err := s.cfg.Menu.Get(ctx, e.ParentID); err == nil {
			backLabel, backHref = p.Label, submenuPath(p.ID)
		}
	}
	s.render(w, r, http.StatusOK, e.Label, "menu-page", map[string]any{"Links": links, "BackLabel": backLabel, "BackHref": backHref})
}

// handleAdmin lists the staff pages the member may use: the web side of
// the Administration item.
func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	sess := s.member(w, r)
	if sess == nil {
		return
	}
	set, err := s.cfg.Perms.Permissions(r.Context(), sess.UserID)
	if err != nil {
		LoggerFrom(r.Context()).Error("administration page: permissions", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
		return
	}
	links := s.adminLinks(set)
	if len(links) == 0 {
		s.renderError(w, r, http.StatusForbidden, "You do not have permission to use Administration.")
		return
	}
	s.render(w, r, http.StatusOK, "Administration", "menu-page", map[string]any{"Links": links, "BackLabel": "Home", "BackHref": "/home"})
}
