package web

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/menu"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// The menu editor: arrange the member menu, for holders of
// core.menu.manage. menu.Service re-checks the permission and audits every
// change; Administration can never be deleted.

// MenuItems describes the menu items core and plugins provide, for the
// menu editor. bbs.Handler implements it.
type MenuItems interface {
	MenuDefaults() []menu.Default
	ItemExists(target string) bool
	ItemLabel(target string) (string, bool)
}

var menuNotices = map[string]string{
	"added":   "The entry has been added.",
	"saved":   "The entry has been saved.",
	"moved":   "The entry has been moved.",
	"deleted": "The entry has been deleted.",
	"reset":   "The default menu has been restored.",
}

type menuRow struct {
	ID                      int64
	Position                int
	Label, What, Permission string
	Submenu, First, Last    bool
}

type permSelect struct {
	ID, Selected string
	Options      []perm.Permission
}

func (s *Server) menuStaff(w http.ResponseWriter, r *http.Request) *websess.Session {
	return s.requirePerm(w, r, perm.MenuManage, "You do not have permission to edit the menu.")
}

// describeTarget says what an entry opens, as the SSH editor does.
func (s *Server) describeTarget(e menu.Entry) string {
	switch {
	case e.Kind == menu.KindSubmenu:
		return "Submenu"
	case s.cfg.MenuItems.ItemExists(e.Target):
		return e.Target
	}
	return e.Target + " (missing: hidden from members)"
}

// menuErrorText words a menu service error for the page; "" means it is
// not an expected one.
func menuErrorText(err error) string {
	switch {
	case errors.Is(err, menu.ErrProtected):
		return "Administration cannot be deleted, so nobody is ever locked out of it. You can rename or move it."
	case errors.Is(err, menu.ErrNotEmpty):
		return "Remove the entries in this submenu first."
	case errors.Is(err, menu.ErrInvalid):
		msg := strings.TrimPrefix(err.Error(), menu.ErrInvalid.Error()+": ")
		return strings.ToUpper(msg[:1]) + msg[1:] + "."
	case errors.Is(err, perm.ErrForbidden):
		return "You do not have permission to edit the menu."
	}
	return ""
}

// parentOf returns the submenu named by ?parent= (0 = main menu) and the
// place to go back to; ok is false if it is not a submenu.
func (s *Server) parentOf(r *http.Request, raw string) (parent menu.Entry, ok bool) {
	if raw == "" || raw == "0" {
		return menu.Entry{}, true
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return menu.Entry{}, false
	}
	e, err := s.cfg.Menu.Get(r.Context(), id)
	if err != nil || e.Kind != menu.KindSubmenu {
		return menu.Entry{}, false
	}
	return e, true
}

func menuPath(parent int64) string {
	if parent == 0 {
		return "/admin/menu"
	}
	return "/admin/menu?parent=" + strconv.FormatInt(parent, 10)
}

// withDone adds a fixed notice code to a menu path.
func withDone(path, code string) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "done=" + url.QueryEscape(code)
}

func (s *Server) menuLabel(r *http.Request, id int64) string {
	if id == 0 {
		return "the main menu"
	}
	if e, err := s.cfg.Menu.Get(r.Context(), id); err == nil {
		return e.Label
	}
	return "the main menu"
}

func (s *Server) targetOptions() []optionView {
	var out []optionView
	for _, d := range s.cfg.MenuItems.MenuDefaults() {
		out = append(out, optionView{Value: d.Target, Label: d.Label + " (" + d.Target + ")"})
	}
	return out
}

func (s *Server) renderMenu(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, parent menu.Entry, add, addErrs map[string]string, errMsg string) {
	entries, err := s.cfg.Menu.Children(r.Context(), parent.ID)
	if err != nil {
		LoggerFrom(r.Context()).Error("menu editor: entries", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "The menu could not be read. Please try again.")
		return
	}
	rows := make([]menuRow, 0, len(entries))
	for i, e := range entries {
		rows = append(rows, menuRow{ID: e.ID, Position: i + 1, Label: e.Label, What: s.describeTarget(e), Permission: e.Permission,
			Submenu: e.Kind == menu.KindSubmenu, First: i == 0, Last: i == len(entries)-1})
	}
	where, title := "the main menu", "Menu editor"
	if parent.ID != 0 {
		where, title = "the submenu "+parent.Label, "Menu editor: "+parent.Label
	}
	if add == nil {
		add = map[string]string{}
	}
	s.render(w, r, status, title, "menu-editor", map[string]any{
		"Notice": menuNotices[r.URL.Query().Get("done")], "Error": errMsg,
		"Parent": parent.ID, "Up": menuPath(parent.ParentID), "UpLabel": s.menuLabel(r, parent.ParentID),
		"Where": where, "Entries": rows, "CSRF": sess.CSRF, "MaxLabel": menu.MaxLabelLen,
		"Targets": s.targetOptions(), "Add": add, "AddErrors": addErrs,
		"AddPerm": permSelect{ID: "add-perm", Selected: add["perm"], Options: s.cfg.Perms.Registry().All()},
	})
}

func (s *Server) handleMenu(w http.ResponseWriter, r *http.Request) {
	sess := s.menuStaff(w, r)
	if sess == nil {
		return
	}
	parent, ok := s.parentOf(r, r.URL.Query().Get("parent"))
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "That submenu does not exist.")
		return
	}
	s.renderMenu(w, r, http.StatusOK, sess, parent, nil, nil, "")
}

// menuForm parses and checks a POST; it answers the request and returns
// nil if the session or token is not valid.
func (s *Server) menuForm(w http.ResponseWriter, r *http.Request) *websess.Session {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess := s.menuStaff(w, r)
	if sess == nil {
		return nil
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return nil
	}
	return sess
}

func (s *Server) handleMenuAdd(w http.ResponseWriter, r *http.Request) {
	sess := s.menuForm(w, r)
	if sess == nil {
		return
	}
	parent, ok := s.parentOf(r, r.PostForm.Get("parent"))
	if !ok {
		s.renderError(w, r, http.StatusNotFound, "That submenu does not exist.")
		return
	}
	add := map[string]string{
		"kind": r.PostForm.Get("kind"), "target": r.PostForm.Get("target"),
		"label": r.PostForm.Get("label"), "perm": r.PostForm.Get("perm"),
	}
	e := menu.Entry{ParentID: parent.ID, Kind: add["kind"], Target: add["target"], Label: add["label"], Permission: add["perm"]}
	errs := map[string]string{}
	switch {
	case e.Kind == menu.KindItem && e.Target == "":
		errs["target"] = "Choose the menu item."
	case e.Kind == menu.KindSubmenu && strings.TrimSpace(e.Label) == "":
		errs["label"] = "A submenu needs a label."
	case e.Kind == menu.KindItem && strings.TrimSpace(e.Label) == "":
		e.Label, _ = s.cfg.MenuItems.ItemLabel(e.Target)
	default:
		if _, err := menu.CleanLabel(e.Label); err != nil {
			errs["label"] = menuErrorText(err)
		}
	}
	if len(errs) > 0 {
		s.renderMenu(w, r, http.StatusUnprocessableEntity, sess, parent, add, errs, "The entry was not added. Correct the fields marked below.")
		return
	}
	if _, err := s.cfg.Menu.Add(r.Context(), sess.UserID, e, s.cfg.MenuItems.ItemExists); err != nil {
		msg := menuErrorText(err)
		if msg == "" {
			s.menuFailure(w, r, err)
			return
		}
		s.renderMenu(w, r, http.StatusUnprocessableEntity, sess, parent, add, errs, "The entry was not added: "+msg)
		return
	}
	http.Redirect(w, r, withDone(menuPath(parent.ID), "added"), http.StatusSeeOther)
}

// entry loads the entry named in the path.
func (s *Server) entry(w http.ResponseWriter, r *http.Request) (menu.Entry, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		if e, err := s.cfg.Menu.Get(r.Context(), id); err == nil {
			return e, true
		}
	}
	s.renderError(w, r, http.StatusNotFound, "That menu entry does not exist.")
	return menu.Entry{}, false
}

func (s *Server) renderEntry(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, e menu.Entry, label, permission, labelErr, errMsg string) {
	s.render(w, r, status, "Menu entry: "+e.Label, "menu-entry", map[string]any{
		"ID": e.ID, "What": "Opens: " + s.describeTarget(e), "Label": label, "LabelError": labelErr, "Error": errMsg,
		"CSRF": sess.CSRF, "MaxLabel": menu.MaxLabelLen, "Protected": e.Target == menu.TargetAdmin,
		"PermSelect": permSelect{ID: "perm", Selected: permission, Options: s.cfg.Perms.Registry().All()},
		"Back":       menuPath(e.ParentID), "BackLabel": s.menuLabel(r, e.ParentID),
	})
}

func (s *Server) handleMenuEntry(w http.ResponseWriter, r *http.Request) {
	sess := s.menuStaff(w, r)
	if sess == nil {
		return
	}
	if e, ok := s.entry(w, r); ok {
		s.renderEntry(w, r, http.StatusOK, sess, e, e.Label, e.Permission, "", "")
	}
}

func (s *Server) handleMenuUpdate(w http.ResponseWriter, r *http.Request) {
	sess := s.menuForm(w, r)
	if sess == nil {
		return
	}
	e, ok := s.entry(w, r)
	if !ok {
		return
	}
	label, permission := r.PostForm.Get("label"), r.PostForm.Get("perm")
	if _, err := menu.CleanLabel(label); err != nil {
		s.renderEntry(w, r, http.StatusUnprocessableEntity, sess, e, label, permission, menuErrorText(err), "The entry was not saved. Correct the label.")
		return
	}
	if err := s.cfg.Menu.Update(r.Context(), sess.UserID, e.ID, label, permission); err != nil {
		msg := menuErrorText(err)
		if msg == "" {
			s.menuFailure(w, r, err)
			return
		}
		s.renderEntry(w, r, http.StatusUnprocessableEntity, sess, e, label, permission, "", "The entry was not saved: "+msg)
		return
	}
	http.Redirect(w, r, withDone(menuPath(e.ParentID), "saved"), http.StatusSeeOther)
}

func (s *Server) handleMenuMove(w http.ResponseWriter, r *http.Request) {
	sess := s.menuForm(w, r)
	if sess == nil {
		return
	}
	e, ok := s.entry(w, r)
	if !ok {
		return
	}
	delta := 1
	switch r.PostForm.Get("direction") {
	case "up":
		delta = -1
	case "down":
	default:
		s.renderError(w, r, http.StatusBadRequest, "Choose Move up or Move down.")
		return
	}
	if err := s.cfg.Menu.Move(r.Context(), sess.UserID, e.ID, delta); err != nil {
		s.menuFailure(w, r, err)
		return
	}
	http.Redirect(w, r, withDone(menuPath(e.ParentID), "moved")+"#entry-"+strconv.FormatInt(e.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleMenuDelete(w http.ResponseWriter, r *http.Request) {
	sess := s.menuForm(w, r)
	if sess == nil {
		return
	}
	e, ok := s.entry(w, r)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != "yes" {
		s.renderEntry(w, r, http.StatusUnprocessableEntity, sess, e, e.Label, e.Permission, "", "Tick the box to confirm, then try again.")
		return
	}
	if err := s.cfg.Menu.Delete(r.Context(), sess.UserID, e.ID); err != nil {
		if msg := menuErrorText(err); msg != "" {
			s.renderEntry(w, r, http.StatusUnprocessableEntity, sess, e, e.Label, e.Permission, "", msg)
			return
		}
		s.menuFailure(w, r, err)
		return
	}
	http.Redirect(w, r, withDone(menuPath(e.ParentID), "deleted"), http.StatusSeeOther)
}

func (s *Server) handleMenuReset(w http.ResponseWriter, r *http.Request) {
	sess := s.menuForm(w, r)
	if sess == nil {
		return
	}
	if r.PostForm.Get("confirm") != "yes" {
		s.renderMenu(w, r, http.StatusUnprocessableEntity, sess, menu.Entry{}, nil, nil, "Tick the box to confirm the reset, then try again.")
		return
	}
	if err := s.cfg.Menu.Reset(r.Context(), sess.UserID, s.cfg.MenuItems.MenuDefaults()); err != nil {
		s.menuFailure(w, r, err)
		return
	}
	http.Redirect(w, r, withDone("/admin/menu", "reset"), http.StatusSeeOther)
}

func (s *Server) menuFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, perm.ErrForbidden):
		s.renderError(w, r, http.StatusForbidden, "You do not have permission to edit the menu.")
	case errors.Is(err, menu.ErrNotFound):
		s.renderError(w, r, http.StatusNotFound, "That menu entry does not exist.")
	default:
		LoggerFrom(r.Context()).Error("menu editor", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "The menu could not be changed. Please try again.")
	}
}
