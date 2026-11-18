package web

import (
	"errors"
	"net/http"
	"strconv"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Accounts awaiting approval, for holders of core.users.approve. The auth
// service re-checks the permission and that the actor holds every
// permission the account would receive.

var pendingNotices = map[string]string{
	"approved": "The account has been approved.",
	"rejected": "The account has been rejected and deleted.",
	"gone":     "That account is no longer waiting for approval.",
}

const errPendingRank = "You cannot act on that account: it would receive permissions you do not have."

type pendingRow struct {
	ID                   int64
	Username, Registered string
}

func (s *Server) approver(w http.ResponseWriter, r *http.Request) *websess.Session {
	return s.requirePerm(w, r, perm.UsersApprove, "You do not have permission to approve accounts.")
}

func (s *Server) handlePending(w http.ResponseWriter, r *http.Request) {
	sess := s.approver(w, r)
	if sess == nil {
		return
	}
	s.renderPending(w, r, http.StatusOK, sess, "")
}

func (s *Server) renderPending(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, errMsg string) {
	users, err := s.cfg.Auth.PendingUsers(r.Context(), sess.UserID)
	if err != nil {
		s.pendingFailure(w, r, err)
		return
	}
	rows := make([]pendingRow, 0, len(users))
	for _, u := range users {
		rows = append(rows, pendingRow{ID: u.ID, Username: u.Username, Registered: fmtSince(u.CreatedAt)})
	}
	s.render(w, r, status, "Accounts awaiting approval", "pending", map[string]any{
		"Rows": rows, "CSRF": sess.CSRF, "Notice": pendingNotices[r.URL.Query().Get("done")], "Error": errMsg,
	})
}

// pendingUser finds the waiting account named in the path.
func (s *Server) pendingUser(r *http.Request, actor int64) (auth.User, bool, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return auth.User{}, false, nil
	}
	users, err := s.cfg.Auth.PendingUsers(r.Context(), actor)
	if err != nil {
		return auth.User{}, false, err
	}
	for _, u := range users {
		if u.ID == id {
			return u, true, nil
		}
	}
	return auth.User{}, false, nil
}

// pendingPost checks the session and token of a POST; it answers the
// request and returns nil if they are not valid.
func (s *Server) pendingPost(w http.ResponseWriter, r *http.Request) *websess.Session {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess := s.approver(w, r)
	if sess == nil {
		return nil
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return nil
	}
	return sess
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	sess := s.pendingPost(w, r)
	if sess == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Redirect(w, r, "/admin/pending?done=gone", http.StatusSeeOther)
		return
	}
	switch err := s.cfg.Auth.Approve(r.Context(), sess.UserID, id); {
	case errors.Is(err, auth.ErrNotPending):
		http.Redirect(w, r, "/admin/pending?done=gone", http.StatusSeeOther)
	case errors.Is(err, perm.ErrForbidden):
		s.renderPending(w, r, http.StatusForbidden, sess, errPendingRank)
	case err != nil:
		s.pendingFailure(w, r, err)
	default:
		LoggerFrom(r.Context()).Info("account approved from the web", "actor", sess.UserID, "user_id", id)
		http.Redirect(w, r, "/admin/pending?done=approved", http.StatusSeeOther)
	}
}

func (s *Server) renderReject(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, u auth.User, errMsg string) {
	s.render(w, r, status, "Reject an account", "pending-reject", map[string]any{
		"ID": u.ID, "Username": u.Username, "Registered": fmtSince(u.CreatedAt), "CSRF": sess.CSRF, "Error": errMsg,
	})
}

func (s *Server) handleRejectConfirm(w http.ResponseWriter, r *http.Request) {
	sess := s.approver(w, r)
	if sess == nil {
		return
	}
	u, ok, err := s.pendingUser(r, sess.UserID)
	switch {
	case err != nil:
		s.pendingFailure(w, r, err)
	case !ok:
		http.Redirect(w, r, "/admin/pending?done=gone", http.StatusSeeOther)
	default:
		s.renderReject(w, r, http.StatusOK, sess, u, "")
	}
}

func (s *Server) handleReject(w http.ResponseWriter, r *http.Request) {
	sess := s.pendingPost(w, r)
	if sess == nil {
		return
	}
	u, ok, err := s.pendingUser(r, sess.UserID)
	switch {
	case err != nil:
		s.pendingFailure(w, r, err)
		return
	case !ok:
		http.Redirect(w, r, "/admin/pending?done=gone", http.StatusSeeOther)
		return
	case r.PostForm.Get("confirm") != "yes":
		s.renderReject(w, r, http.StatusUnprocessableEntity, sess, u, "Tick the box to confirm, then try again.")
		return
	}
	switch err := s.cfg.Auth.Reject(r.Context(), sess.UserID, u.ID); {
	case errors.Is(err, auth.ErrNotPending):
		http.Redirect(w, r, "/admin/pending?done=gone", http.StatusSeeOther)
	case errors.Is(err, perm.ErrForbidden):
		s.renderReject(w, r, http.StatusForbidden, sess, u, errPendingRank)
	case err != nil:
		s.pendingFailure(w, r, err)
	default:
		LoggerFrom(r.Context()).Info("account rejected from the web", "actor", sess.UserID, "user_id", u.ID)
		http.Redirect(w, r, "/admin/pending?done=rejected", http.StatusSeeOther)
	}
}

func (s *Server) pendingFailure(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, perm.ErrForbidden) {
		s.renderError(w, r, http.StatusForbidden, "You do not have permission to approve accounts.")
		return
	}
	LoggerFrom(r.Context()).Error("accounts awaiting approval", "err", err)
	s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
}
