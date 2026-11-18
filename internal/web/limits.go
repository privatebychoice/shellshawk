package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/settings"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Connection limits: the SSH idle timeout and connections per account, for
// holders of core.settings.manage. settings.Service re-checks the
// permission when saving.

// errSettingsForbidden is shown to members without core.settings.manage.
const errSettingsForbidden = "You do not have permission to change system settings."

// settingsStaff returns the session of a member allowed to change system
// settings. It answers the request itself (redirect or error) and returns
// nil otherwise.
func (s *Server) settingsStaff(w http.ResponseWriter, r *http.Request) *websess.Session {
	sess := sessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil
	}
	if ok, err := s.cfg.Perms.Has(r.Context(), sess.UserID, perm.SettingsManage); err != nil || !ok {
		s.renderError(w, r, http.StatusForbidden, errSettingsForbidden)
		return nil
	}
	return sess
}

func (s *Server) renderLimits(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, values, errs map[string]string, notice string) {
	s.render(w, r, status, "Connection limits", "limits", map[string]any{
		"CSRF": sess.CSRF, "Values": values, "Errors": errs, "Notice": notice,
		"MinIdle": settings.MinIdleMinutes, "MaxIdle": settings.MaxIdleMinutes, "MaxPerUser": settings.MaxMaxPerUser,
	})
}

func (s *Server) handleLimits(w http.ResponseWriter, r *http.Request) {
	sess := s.settingsStaff(w, r)
	if sess == nil {
		return
	}
	cur := s.cfg.Settings.ConnLimits(r.Context())
	notice := ""
	if r.URL.Query().Get("done") == "saved" {
		notice = "Connection limits saved."
	}
	s.renderLimits(w, r, http.StatusOK, sess, map[string]string{
		"idle": strconv.Itoa(cur.IdleMinutes), "max": strconv.Itoa(cur.MaxPerUser),
	}, nil, notice)
}

// limitField parses one whole-number field and checks it.
func limitField(v string, check func(int) error) (int, string) {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return 0, "Enter a whole number."
	}
	if err := check(n); err != nil {
		msg := strings.TrimPrefix(err.Error(), settings.ErrInvalid.Error()+": ")
		return 0, strings.ToUpper(msg[:1]) + msg[1:] + "."
	}
	return n, ""
}

func (s *Server) handleLimitsSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess := s.settingsStaff(w, r)
	if sess == nil {
		return
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return
	}
	values := map[string]string{"idle": r.PostForm.Get("idle"), "max": r.PostForm.Get("max")}
	errs := map[string]string{}
	idle, msg := limitField(values["idle"], settings.CheckIdleMinutes)
	if msg != "" {
		errs["idle"] = msg
	}
	maxConns, msg := limitField(values["max"], settings.CheckMaxPerUser)
	if msg != "" {
		errs["max"] = msg
	}
	if len(errs) > 0 {
		s.renderLimits(w, r, http.StatusUnprocessableEntity, sess, values, errs, "")
		return
	}
	err := s.cfg.Settings.SetConnLimits(r.Context(), sess.UserID, settings.ConnLimits{IdleMinutes: idle, MaxPerUser: maxConns})
	switch {
	case errors.Is(err, perm.ErrForbidden):
		s.renderError(w, r, http.StatusForbidden, errSettingsForbidden)
	case err != nil:
		LoggerFrom(r.Context()).Error("save connection limits", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "The limits could not be saved. Please try again.")
	default:
		LoggerFrom(r.Context()).Info("connection limits changed from the web", "actor", sess.UserID)
		http.Redirect(w, r, "/admin/limits?done=saved", http.StatusSeeOther)
	}
}
