package web

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/privacy"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Users: find an account, lock or unlock it, cancel an erasure request or
// show its email address (core.users.manage), and change its groups
// (core.groups.manage). The services check every permission, the rank
// rule and the last-administrator guard, and audit.

var userNotices = map[string]string{
	"locked":    "The account has been locked. Its SSH connections and web sessions have ended.",
	"unlocked":  "The account has been unlocked.",
	"cancelled": "The erasure request has been cancelled and the account reactivated.",
	"added":     "The account has been added to the group.",
	"removed":   "The account has been removed from the group.",
}

type userRow struct {
	ID                                      int64
	Username, Status, Registered, LastLogin string
}

func (s *Server) userAdmin(w http.ResponseWriter, r *http.Request) (*websess.Session, perm.Set) {
	sess := sessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, nil
	}
	set, err := s.cfg.Perms.Permissions(r.Context(), sess.UserID)
	if err != nil || (!set.Has(perm.UsersManage) && !set.Has(perm.GroupsManage)) {
		s.renderError(w, r, http.StatusForbidden, "You do not have permission to manage users.")
		return nil, nil
	}
	return sess, set
}

func lastLogin(u auth.User) string {
	if u.LastLoginAt == nil {
		return "never"
	}
	return fmtSince(*u.LastLoginAt)
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.userAdmin(w, r)
	if sess == nil {
		return
	}
	q, searched := r.URL.Query()["q"]
	query := ""
	if searched {
		query = strings.TrimSpace(q[0])
	}
	var rows []userRow
	if searched {
		users, err := s.cfg.Auth.ListUsers(r.Context(), sess.UserID, query)
		if err != nil {
			s.userFailure(w, r, err)
			return
		}
		for _, u := range users {
			rows = append(rows, userRow{ID: u.ID, Username: u.Username, Status: u.Status, Registered: fmtSince(u.CreatedAt), LastLogin: lastLogin(u)})
		}
	}
	s.render(w, r, http.StatusOK, "Users", "users", map[string]any{
		"Query": query, "Searched": searched, "Rows": rows, "Max": auth.MaxListUsers,
	})
}

// target loads the account named in the path.
func (s *Server) target(w http.ResponseWriter, r *http.Request) (auth.User, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		if u, err := s.cfg.Auth.UserByID(r.Context(), id); err == nil {
			return u, true
		}
	}
	s.renderError(w, r, http.StatusNotFound, "That account does not exist.")
	return auth.User{}, false
}

func (s *Server) renderUser(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, set perm.Set, u auth.User, email, errMsg string) {
	ctx := r.Context()
	groups, err := s.cfg.Perms.UserGroups(ctx, u.ID)
	if err != nil {
		s.userFailure(w, r, err)
		return
	}
	d := map[string]any{
		"ID": u.ID, "Status": u.Status, "Groups": groups, "GroupList": strings.Join(groups, ", "),
		"Registered": fmtSince(u.CreatedAt), "LastLogin": lastLogin(u), "CSRF": sess.CSRF,
		"Notice": userNotices[r.URL.Query().Get("done")], "Error": errMsg, "Email": email,
		"Manage": set.Has(perm.UsersManage), "ManageGroups": set.Has(perm.GroupsManage), "Self": u.ID == sess.UserID,
	}
	erasing, completed := false, false
	if s.cfg.Privacy != nil {
		e, ok, err := s.cfg.Privacy.Erasure(ctx, u.ID)
		if err != nil {
			s.userFailure(w, r, err)
			return
		}
		erasing, completed = ok, ok && e.CompletedAt != nil
		switch {
		case completed:
			d["Erasure"] = "This account was erased on " + fmtSince(*e.CompletedAt) + "."
		case erasing:
			d["Erasure"] = "The member asked for this account to be erased; it will be erased on " + fmtSince(e.EraseAfter) + "."
		}
	}
	switch {
	case completed:
	case erasing:
		d["StatusAction"], d["StatusLabel"], d["StatusConfirm"] = "cancel-erasure", "Cancel the erasure request", "Yes, cancel the erasure and reactivate this account"
	case u.Status == auth.StatusActive:
		d["StatusAction"], d["StatusLabel"], d["StatusConfirm"] = "lock", "Lock account", "Yes, lock this account. Their SSH connections and web sessions end, and they cannot log in until unlocked"
	case u.Status == auth.StatusLocked:
		d["StatusAction"], d["StatusLabel"], d["StatusConfirm"] = "unlock", "Unlock account", "Yes, unlock this account"
	}
	d["CanEmail"] = s.cfg.Privacy != nil && !completed
	if set.Has(perm.GroupsManage) {
		all, err := s.cfg.Perms.Groups(ctx)
		if err != nil {
			s.userFailure(w, r, err)
			return
		}
		var joinable, leavable []perm.Group
		for _, g := range all {
			if slices.Contains(groups, g.Name) {
				leavable = append(leavable, g)
			} else {
				joinable = append(joinable, g)
			}
		}
		d["Joinable"], d["Leavable"] = joinable, leavable
	}
	s.render(w, r, status, "User "+u.Username, "user", d)
}

func (s *Server) handleUser(w http.ResponseWriter, r *http.Request) {
	sess, set := s.userAdmin(w, r)
	if sess == nil {
		return
	}
	if u, ok := s.target(w, r); ok {
		s.renderUser(w, r, http.StatusOK, sess, set, u, "", "")
	}
}

// userPost checks a POST's session and token and loads its account.
func (s *Server) userPost(w http.ResponseWriter, r *http.Request) (*websess.Session, perm.Set, auth.User, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess, set := s.userAdmin(w, r)
	if sess == nil {
		return nil, nil, auth.User{}, false
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return nil, nil, auth.User{}, false
	}
	u, ok := s.target(w, r)
	return sess, set, u, ok
}

// userDone redirects to the account's page with a fixed notice, or shows
// the page again with the error worded for staff.
func (s *Server) userDone(w http.ResponseWriter, r *http.Request, sess *websess.Session, set perm.Set, u auth.User, err error, done string) {
	if err == nil {
		LoggerFrom(r.Context()).Info("account changed from the web", "actor", sess.UserID, "user_id", u.ID, "change", done)
		http.Redirect(w, r, "/admin/users/"+strconv.FormatInt(u.ID, 10)+"?done="+done, http.StatusSeeOther)
		return
	}
	msg, status := userErrorText(err)
	if msg == "" {
		s.userFailure(w, r, err)
		return
	}
	if fresh, ferr := s.cfg.Auth.UserByID(r.Context(), u.ID); ferr == nil {
		u = fresh
	}
	s.renderUser(w, r, status, sess, set, u, "", msg)
}

func userErrorText(err error) (string, int) {
	switch {
	case errors.Is(err, perm.ErrForbidden):
		return "You do not have permission to do that. It may involve permissions you do not hold yourself.", http.StatusForbidden
	case errors.Is(err, perm.ErrLastAdmin):
		return "That would leave the BBS without an active administrator, so it was not done.", http.StatusConflict
	case errors.Is(err, perm.ErrProtected):
		return "Built-in groups cannot be changed that way.", http.StatusConflict
	case errors.Is(err, auth.ErrSelf):
		return "You cannot do that to your own account.", http.StatusConflict
	case errors.Is(err, auth.ErrErasurePending):
		return "This account is waiting to be erased; cancel the erasure request instead.", http.StatusConflict
	case errors.Is(err, auth.ErrNotFound), errors.Is(err, privacy.ErrNoRequest):
		return "The account has changed since the page was shown. Check its status and try again.", http.StatusConflict
	}
	return "", 0
}

// confirmed refuses an action whose box was not ticked.
func (s *Server) userConfirmed(w http.ResponseWriter, r *http.Request, sess *websess.Session, set perm.Set, u auth.User) bool {
	if r.PostForm.Get("confirm") == "yes" {
		return true
	}
	s.renderUser(w, r, http.StatusUnprocessableEntity, sess, set, u, "", "Tick the box to confirm, then try again.")
	return false
}

func (s *Server) handleUserLock(w http.ResponseWriter, r *http.Request) {
	sess, set, u, ok := s.userPost(w, r)
	if !ok || !s.userConfirmed(w, r, sess, set, u) {
		return
	}
	lock := strings.HasSuffix(r.URL.Path, "/lock")
	done := "unlocked"
	if lock {
		done = "locked"
	}
	s.userDone(w, r, sess, set, u, s.cfg.Auth.SetLocked(r.Context(), sess.UserID, u.ID, lock), done)
}

func (s *Server) handleUserCancelErasure(w http.ResponseWriter, r *http.Request) {
	sess, set, u, ok := s.userPost(w, r)
	if !ok || !s.userConfirmed(w, r, sess, set, u) {
		return
	}
	if s.cfg.Privacy == nil {
		s.renderError(w, r, http.StatusNotFound, "Page not found.")
		return
	}
	s.userDone(w, r, sess, set, u, s.cfg.Privacy.CancelErasure(r.Context(), sess.UserID, u.ID), "cancelled")
}

// handleUserEmail shows the address on the page that answers the POST: it
// is audited, so it is never fetched by a GET a browser might prefetch,
// and never put in a URL.
func (s *Server) handleUserEmail(w http.ResponseWriter, r *http.Request) {
	sess, set, u, ok := s.userPost(w, r)
	if !ok {
		return
	}
	if s.cfg.Privacy == nil {
		s.renderError(w, r, http.StatusNotFound, "Page not found.")
		return
	}
	if u.ID == sess.UserID {
		s.userDone(w, r, sess, set, u, auth.ErrSelf, "")
		return
	}
	email, err := s.cfg.Privacy.AdminEmail(r.Context(), sess.UserID, u.ID)
	if err != nil {
		s.userDone(w, r, sess, set, u, err, "")
		return
	}
	if email == "" {
		email = "none given"
	}
	LoggerFrom(r.Context()).Info("email address shown on the web", "actor", sess.UserID, "user_id", u.ID)
	s.renderUser(w, r, http.StatusOK, sess, set, u, email, "")
}

func (s *Server) handleUserGroup(w http.ResponseWriter, r *http.Request) {
	sess, set, u, ok := s.userPost(w, r)
	if !ok {
		return
	}
	gid, err := strconv.ParseInt(r.PostForm.Get("group"), 10, 64)
	if err != nil {
		s.renderUser(w, r, http.StatusUnprocessableEntity, sess, set, u, "", "Choose a group.")
		return
	}
	if strings.HasSuffix(r.URL.Path, "/add") {
		s.userDone(w, r, sess, set, u, s.cfg.Perms.AddMember(r.Context(), sess.UserID, gid, u.ID), "added")
		return
	}
	s.userDone(w, r, sess, set, u, s.cfg.Perms.RemoveMember(r.Context(), sess.UserID, gid, u.ID), "removed")
}

func (s *Server) userFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, perm.ErrForbidden) {
		s.renderError(w, r, http.StatusForbidden, "You do not have permission to manage users.")
		return
	}
	LoggerFrom(r.Context()).Error("users", "err", err)
	s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
}
