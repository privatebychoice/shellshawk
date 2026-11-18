package web

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/sessions"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Who is online: the open SSH connections, for staff holding
// core.sessions.manage, with a way to end one. The sessions service
// re-checks the permission and the actor's rank on every request.

// onlineNotices are confirmations after a redirect (?done=…): fixed text
// only, never echoed from the URL.
var onlineNotices = map[string]string{
	"ended":     "The connection has been ended.",
	"gone":      "That connection had already closed.",
	"web-ended": "The web session has been logged out.",
	"web-gone":  "That web session had already ended.",
}

type webRow struct {
	ID, Who, Active, Since, Expires string
	Own                             bool // the viewer's own session
}

type onlineRow struct {
	ID                     uint64
	Who, Uses, Idle, Since string
}

func fmtSince(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// staff returns the session of a member allowed to manage connections. It
// answers the request itself (redirect or error) and returns nil otherwise.
func (s *Server) staff(w http.ResponseWriter, r *http.Request) *websess.Session {
	sess := sessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil
	}
	if ok, err := s.cfg.Perms.Has(r.Context(), sess.UserID, perm.SessionsManage); err != nil || !ok {
		s.renderError(w, r, http.StatusForbidden, "You do not have permission to see who is online.")
		return nil
	}
	return sess
}

func (s *Server) handleOnline(w http.ResponseWriter, r *http.Request) {
	sess := s.staff(w, r)
	if sess == nil {
		return
	}
	conns, err := s.cfg.Connections.List(r.Context(), sess.UserID)
	if err != nil {
		s.connectionError(w, r, err)
		return
	}
	webs, err := s.cfg.Connections.WebSessions(r.Context(), sess.UserID)
	if err != nil {
		s.connectionError(w, r, err)
		return
	}
	now := time.Now()
	rows := make([]onlineRow, 0, len(conns))
	for _, c := range conns {
		rows = append(rows, onlineRow{ID: c.ID, Who: c.Who(), Uses: c.Uses(), Idle: c.Idle(now), Since: fmtSince(c.Started)})
	}
	webRows := make([]webRow, 0, len(webs))
	for _, ws := range webs {
		webRows = append(webRows, webRow{ID: ws.ID, Who: ws.Who(), Active: ws.Active(now), Since: fmtSince(ws.Created),
			Expires: fmtSince(ws.Expires), Own: ws.ID == sess.ID})
	}
	s.render(w, r, http.StatusOK, "Who is online", "online", map[string]any{
		"Notice": onlineNotices[r.URL.Query().Get("done")], "Count": len(rows), "Rows": rows,
		"Web": s.cfg.Connections.HasWeb(), "WebRows": webRows,
	})
}

// connection finds an open connection by its path ID.
func (s *Server) connection(r *http.Request, actor int64) (sessions.Connection, bool, error) {
	id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
	if err != nil {
		return sessions.Connection{}, false, nil
	}
	conns, err := s.cfg.Connections.List(r.Context(), actor)
	if err != nil {
		return sessions.Connection{}, false, err
	}
	for _, c := range conns {
		if c.ID == id {
			return c, true, nil
		}
	}
	return sessions.Connection{}, false, nil
}

func (s *Server) renderEnd(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, c sessions.Connection, msg string) {
	s.render(w, r, status, "End a connection", "online-end", map[string]any{
		"ID": c.ID, "Describe": c.Describe(time.Now()), "Since": fmtSince(c.Started), "CSRF": sess.CSRF, "Error": msg,
	})
}

func (s *Server) handleOnlineConfirm(w http.ResponseWriter, r *http.Request) {
	sess := s.staff(w, r)
	if sess == nil {
		return
	}
	c, ok, err := s.connection(r, sess.UserID)
	switch {
	case err != nil:
		s.connectionError(w, r, err)
	case !ok:
		http.Redirect(w, r, "/admin/online?done=gone", http.StatusSeeOther)
	default:
		s.renderEnd(w, r, http.StatusOK, sess, c, "")
	}
}

func (s *Server) handleOnlineEnd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess := s.staff(w, r)
	if sess == nil {
		return
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return
	}
	c, ok, err := s.connection(r, sess.UserID)
	switch {
	case err != nil:
		s.connectionError(w, r, err)
		return
	case !ok:
		http.Redirect(w, r, "/admin/online?done=gone", http.StatusSeeOther)
		return
	case r.PostForm.Get("confirm") != "yes":
		s.renderEnd(w, r, http.StatusUnprocessableEntity, sess, c, "Tick the box to confirm, then try again.")
		return
	}
	switch err := s.cfg.Connections.End(r.Context(), sess.UserID, c.ID); {
	case errors.Is(err, sessions.ErrNotFound):
		http.Redirect(w, r, "/admin/online?done=gone", http.StatusSeeOther)
	case err != nil:
		s.connectionError(w, r, err)
	default:
		LoggerFrom(r.Context()).Info("connection ended from the web", "actor", sess.UserID, "conn", c.ID)
		http.Redirect(w, r, "/admin/online?done=ended", http.StatusSeeOther)
	}
}

func (s *Server) connectionError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, perm.ErrForbidden) {
		s.renderError(w, r, http.StatusForbidden, "You cannot end that connection: the account has permissions you do not have.")
		return
	}
	LoggerFrom(r.Context()).Error("who is online", "err", err)
	s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

// webSessionFor finds a web session by its path ID; the viewer's own
// session is not offered, as logging out does that.
func (s *Server) webSessionFor(r *http.Request, sess *websess.Session) (sessions.WebSession, bool, error) {
	id := r.PathValue("id")
	if id == sess.ID {
		return sessions.WebSession{}, false, nil
	}
	webs, err := s.cfg.Connections.WebSessions(r.Context(), sess.UserID)
	if err != nil {
		return sessions.WebSession{}, false, err
	}
	for _, ws := range webs {
		if ws.ID == id {
			return ws, true, nil
		}
	}
	return sessions.WebSession{}, false, nil
}

func (s *Server) renderWebEnd(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, ws sessions.WebSession, msg string) {
	s.render(w, r, status, "Log out a web session", "web-session-end", map[string]any{
		"ID": ws.ID, "Who": ws.Who(), "Since": fmtSince(ws.Created), "Active": ws.Active(time.Now()), "CSRF": sess.CSRF, "Error": msg,
	})
}

func (s *Server) handleWebSessionConfirm(w http.ResponseWriter, r *http.Request) {
	sess := s.staff(w, r)
	if sess == nil {
		return
	}
	ws, ok, err := s.webSessionFor(r, sess)
	switch {
	case err != nil:
		s.connectionError(w, r, err)
	case !ok:
		http.Redirect(w, r, "/admin/online?done=web-gone#web", http.StatusSeeOther)
	default:
		s.renderWebEnd(w, r, http.StatusOK, sess, ws, "")
	}
}

func (s *Server) handleWebSessionEnd(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess := s.staff(w, r)
	if sess == nil {
		return
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return
	}
	ws, ok, err := s.webSessionFor(r, sess)
	switch {
	case err != nil:
		s.connectionError(w, r, err)
		return
	case !ok:
		http.Redirect(w, r, "/admin/online?done=web-gone#web", http.StatusSeeOther)
		return
	case r.PostForm.Get("confirm") != "yes":
		s.renderWebEnd(w, r, http.StatusUnprocessableEntity, sess, ws, "Tick the box to confirm, then try again.")
		return
	}
	switch err := s.cfg.Connections.EndWeb(r.Context(), sess.UserID, ws.ID); {
	case errors.Is(err, sessions.ErrNotFound):
		http.Redirect(w, r, "/admin/online?done=web-gone#web", http.StatusSeeOther)
	case err != nil:
		s.connectionError(w, r, err)
	default:
		LoggerFrom(r.Context()).Info("web session ended from the web", "actor", sess.UserID)
		http.Redirect(w, r, "/admin/online?done=web-ended#web", http.StatusSeeOther)
	}
}
