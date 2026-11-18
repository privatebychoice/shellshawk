package web

import (
	"errors"
	"net/http"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/settings"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Branding: the BBS name, for holders of core.settings.manage.

func (s *Server) renderBranding(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, name, errMsg, notice string) {
	s.render(w, r, status, "Branding", "branding", map[string]any{
		"CSRF": sess.CSRF, "Name": name, "Error": errMsg, "Notice": notice, "MaxLen": settings.MaxBBSNameLen,
	})
}

func (s *Server) handleBranding(w http.ResponseWriter, r *http.Request) {
	sess := s.settingsStaff(w, r)
	if sess == nil {
		return
	}
	notice := ""
	if r.URL.Query().Get("done") == "saved" {
		notice = "The BBS name has been changed."
	}
	s.renderBranding(w, r, http.StatusOK, sess, s.cfg.Settings.BBSName(r.Context()), "", notice)
}

func (s *Server) handleBrandingSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess := s.settingsStaff(w, r)
	if sess == nil {
		return
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return
	}
	name := r.PostForm.Get("name")
	err := s.cfg.Settings.SetBBSName(r.Context(), sess.UserID, name)
	switch {
	case errors.Is(err, settings.ErrInvalid):
		msg := strings.TrimPrefix(err.Error(), settings.ErrInvalid.Error()+": ")
		s.renderBranding(w, r, http.StatusUnprocessableEntity, sess, name, "The "+msg+".", "")
	case errors.Is(err, perm.ErrForbidden):
		s.renderError(w, r, http.StatusForbidden, errSettingsForbidden)
	case err != nil:
		LoggerFrom(r.Context()).Error("save BBS name", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "The name could not be saved. Please try again.")
	default:
		LoggerFrom(r.Context()).Info("BBS name changed from the web", "actor", sess.UserID)
		http.Redirect(w, r, "/admin/branding?done=saved", http.StatusSeeOther)
	}
}
