package web

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Groups and permissions, for holders of core.groups.manage. perm.Service
// checks the permission, that the actor holds every permission involved,
// the built-in groups and the last-administrator guard, and audits.

var groupNotices = map[string]string{
	"created": "The group has been created. Grant it permissions below.",
	"granted": "The permission has been granted.",
	"revoked": "The permission has been revoked.",
	"added":   "The member has been added.",
	"removed": "The member has been removed.",
	"deleted": "The group has been deleted.",
}

type groupRow struct {
	ID                int64
	Name, Description string
	Perms, Members    int
	Builtin           bool
}

func (s *Server) groupAdmin(w http.ResponseWriter, r *http.Request) *websess.Session {
	return s.requirePerm(w, r, perm.GroupsManage, "You do not have permission to manage groups.")
}

func groupForm() *form.Form {
	return &form.Form{Fields: []form.Field{
		{Name: "name", Label: "Name", Kind: form.SingleLine, Required: true, MinLen: 2, MaxLen: 32,
			Help: "Lowercase letters, digits, '_' or '-', starting with a letter."},
		{Name: "desc", Label: "Description", Kind: form.SingleLine, MaxLen: 200},
	}}
}

func (s *Server) renderGroups(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, vals form.Values, errs form.Errors, msg string) {
	groups, err := s.cfg.Perms.Groups(r.Context())
	if err != nil {
		s.groupFailure(w, r, err)
		return
	}
	rows := make([]groupRow, 0, len(groups))
	for _, g := range groups {
		members, err := s.cfg.Perms.GroupMembers(r.Context(), g.ID)
		if err != nil {
			s.groupFailure(w, r, err)
			return
		}
		rows = append(rows, groupRow{ID: g.ID, Name: g.Name, Description: g.Description, Perms: len(g.Permissions), Members: len(members), Builtin: g.Builtin})
	}
	s.render(w, r, status, "Groups and permissions", "groups", map[string]any{
		"Rows": rows, "CSRF": sess.CSRF, "Notice": groupNotices[r.URL.Query().Get("done")],
		"Fields": fieldViews(groupForm(), vals, errs), "Error": msg,
	})
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request) {
	if sess := s.groupAdmin(w, r); sess != nil {
		s.renderGroups(w, r, http.StatusOK, sess, nil, nil, "")
	}
}

// groupPost checks a POST's session and token.
func (s *Server) groupPost(w http.ResponseWriter, r *http.Request) *websess.Session {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess := s.groupAdmin(w, r)
	if sess == nil {
		return nil
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return nil
	}
	return sess
}

func (s *Server) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	sess := s.groupPost(w, r)
	if sess == nil {
		return
	}
	fm := groupForm()
	raw := formValues(fm, r)
	vals, errs := fm.Validate(raw)
	if len(errs) == 0 {
		id, err := s.cfg.Perms.CreateGroup(r.Context(), sess.UserID, vals["name"], vals["desc"])
		switch {
		case errors.Is(err, perm.ErrInvalidGroup):
			errs = form.Errors{"name": errors.New("must be lowercase letters, digits, '_' or '-', starting with a letter")}
		case errors.Is(err, perm.ErrExists):
			errs = form.Errors{"name": errors.New("is already used by another group")}
		case err != nil:
			s.groupFailure(w, r, err)
			return
		default:
			LoggerFrom(r.Context()).Info("group created from the web", "actor", sess.UserID, "group_id", id)
			http.Redirect(w, r, "/admin/groups/"+strconv.FormatInt(id, 10)+"?done=created", http.StatusSeeOther)
			return
		}
	}
	s.renderGroups(w, r, http.StatusUnprocessableEntity, sess, raw, errs, "The group was not created. Correct the fields marked below.")
}

// group loads the group named in the path.
func (s *Server) group(w http.ResponseWriter, r *http.Request) (perm.Group, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		if g, err := s.cfg.Perms.GroupByID(r.Context(), id); err == nil {
			return g, true
		}
	}
	s.renderError(w, r, http.StatusNotFound, "That group does not exist.")
	return perm.Group{}, false
}

func (s *Server) renderGroup(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, g perm.Group, addName, addErr, errMsg string) {
	members, err := s.cfg.Perms.GroupMembers(r.Context(), g.ID)
	if err != nil {
		s.groupFailure(w, r, err)
		return
	}
	var held, grantable []perm.Permission
	for _, p := range s.cfg.Perms.Registry().All() {
		if slices.Contains(g.Permissions, p.Name) {
			held = append(held, p)
		} else {
			grantable = append(grantable, p)
		}
	}
	// A permission no longer registered (its plugin was removed) is still
	// shown so it can be revoked.
	for _, name := range g.Permissions {
		if !s.cfg.Perms.Registry().Known(name) {
			held = append(held, perm.Permission{Name: name, Description: "Not provided by any installed plugin"})
		}
	}
	s.render(w, r, status, "Group "+g.Name, "group", map[string]any{
		"ID": g.ID, "Name": g.Name, "Description": g.Description, "Builtin": g.Builtin,
		"Perms": held, "Grantable": grantable, "Members": members, "CSRF": sess.CSRF,
		"Notice": groupNotices[r.URL.Query().Get("done")], "Error": errMsg, "AddName": addName, "AddError": addErr,
	})
}

func (s *Server) handleGroup(w http.ResponseWriter, r *http.Request) {
	sess := s.groupAdmin(w, r)
	if sess == nil {
		return
	}
	if g, ok := s.group(w, r); ok {
		s.renderGroup(w, r, http.StatusOK, sess, g, "", "", "")
	}
}

// groupDone redirects to the group's page with a fixed notice, or shows
// the page again with the error.
func (s *Server) groupDone(w http.ResponseWriter, r *http.Request, sess *websess.Session, g perm.Group, err error, done string) {
	if err == nil {
		LoggerFrom(r.Context()).Info("group changed from the web", "actor", sess.UserID, "group_id", g.ID, "change", done)
		http.Redirect(w, r, "/admin/groups/"+strconv.FormatInt(g.ID, 10)+"?done="+done, http.StatusSeeOther)
		return
	}
	msg, status := groupErrorText(err)
	if msg == "" {
		s.groupFailure(w, r, err)
		return
	}
	if fresh, ferr := s.cfg.Perms.GroupByID(r.Context(), g.ID); ferr == nil {
		g = fresh
	}
	s.renderGroup(w, r, status, sess, g, "", "", msg)
}

func groupErrorText(err error) (string, int) {
	switch {
	case errors.Is(err, perm.ErrForbidden):
		return "You do not have permission to do that. It may involve permissions you do not hold yourself.", http.StatusForbidden
	case errors.Is(err, perm.ErrLastAdmin):
		return "That would leave the BBS without an active administrator, so it was not done.", http.StatusConflict
	case errors.Is(err, perm.ErrProtected):
		return "Built-in groups cannot be changed that way.", http.StatusConflict
	case errors.Is(err, perm.ErrUnknownPerm):
		return "That permission does not exist.", http.StatusUnprocessableEntity
	case errors.Is(err, perm.ErrNotFound), errors.Is(err, perm.ErrExists):
		return "The group has changed since the page was shown. Check it and try again.", http.StatusConflict
	}
	return "", 0
}

func (s *Server) handleGroupPerm(w http.ResponseWriter, r *http.Request) {
	sess := s.groupPost(w, r)
	if sess == nil {
		return
	}
	g, ok := s.group(w, r)
	if !ok {
		return
	}
	p := r.PostForm.Get("perm")
	if strings.HasSuffix(r.URL.Path, "/grant") {
		s.groupDone(w, r, sess, g, s.cfg.Perms.Grant(r.Context(), sess.UserID, g.ID, p), "granted")
		return
	}
	s.groupDone(w, r, sess, g, s.cfg.Perms.Revoke(r.Context(), sess.UserID, g.ID, p), "revoked")
}

func (s *Server) handleGroupAddMember(w http.ResponseWriter, r *http.Request) {
	sess := s.groupPost(w, r)
	if sess == nil {
		return
	}
	g, ok := s.group(w, r)
	if !ok {
		return
	}
	name := r.PostForm.Get("username")
	u, err := s.cfg.Auth.UserByUsername(r.Context(), name)
	if errors.Is(err, auth.ErrNotFound) {
		s.renderGroup(w, r, http.StatusUnprocessableEntity, sess, g, name, "There is no account with that username.", "")
		return
	}
	if err != nil {
		s.groupFailure(w, r, err)
		return
	}
	s.groupDone(w, r, sess, g, s.cfg.Perms.AddMember(r.Context(), sess.UserID, g.ID, u.ID), "added")
}

func (s *Server) handleGroupRemoveMember(w http.ResponseWriter, r *http.Request) {
	sess := s.groupPost(w, r)
	if sess == nil {
		return
	}
	g, ok := s.group(w, r)
	if !ok {
		return
	}
	uid, err := strconv.ParseInt(r.PostForm.Get("user"), 10, 64)
	if err != nil {
		s.renderGroup(w, r, http.StatusUnprocessableEntity, sess, g, "", "", "Choose a member to remove.")
		return
	}
	s.groupDone(w, r, sess, g, s.cfg.Perms.RemoveMember(r.Context(), sess.UserID, g.ID, uid), "removed")
}

func (s *Server) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	sess := s.groupPost(w, r)
	if sess == nil {
		return
	}
	g, ok := s.group(w, r)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != "yes" {
		s.renderGroup(w, r, http.StatusUnprocessableEntity, sess, g, "", "", "Tick the box to confirm, then try again.")
		return
	}
	if err := s.cfg.Perms.DeleteGroup(r.Context(), sess.UserID, g.ID); err != nil {
		s.groupDone(w, r, sess, g, err, "")
		return
	}
	LoggerFrom(r.Context()).Info("group deleted from the web", "actor", sess.UserID, "group_id", g.ID)
	http.Redirect(w, r, "/admin/groups?done=deleted", http.StatusSeeOther)
}

func (s *Server) groupFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, perm.ErrForbidden) {
		s.renderError(w, r, http.StatusForbidden, "You do not have permission to manage groups.")
		return
	}
	LoggerFrom(r.Context()).Error("groups", "err", err)
	s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
}
