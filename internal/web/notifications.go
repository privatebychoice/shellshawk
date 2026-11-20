package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/notify"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Notifications (docs/DESIGN.md §6.6) on the web: the same list as the SSH
// Notifications item, newest first, with a link to what each is about
// where its plugin has a web page, and the member's notification
// settings. The navigation shows how many are new.

// notificationNotices are confirmations after a redirect (?done=…): fixed
// text only, never echoed from the URL.
var notificationNotices = map[string]string{
	"deleted": "The notification was deleted.",
	"cleared": "All your notifications were deleted.",
	"seen":    "All your notifications are marked as seen.",
	"saved":   "Your notification settings have been saved.",
	"gone":    "That notification no longer exists.",
	"no-web":  "That notification cannot be opened on the web. Open it from Notifications over SSH.",
}

type notificationRow struct {
	ID, Text, Age string
	New, Open     bool
}

// member returns the session of a logged-in member, or redirects to the
// login page and returns nil.
func (s *Server) member(w http.ResponseWriter, r *http.Request) *websess.Session {
	sess := sessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
	return sess
}

// memberPost is member for a form post: it also reads the form and checks
// its CSRF token.
func (s *Server) memberPost(w http.ResponseWriter, r *http.Request) *websess.Session {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess := s.member(w, r)
	if sess == nil {
		return nil
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return nil
	}
	return sess
}

// newNotifications returns how many of user's notifications are new; 0
// on failure, which is logged.
func (s *Server) newNotifications(ctx context.Context, user int64) int {
	if s.cfg.Notify == nil {
		return 0
	}
	n, err := s.cfg.Notify.CountUnseen(ctx, user)
	if err != nil {
		LoggerFrom(ctx).Error("count new notifications", "err", err)
	}
	return n
}

// notificationsLabelFor adds the count of new notifications to the
// Notifications entry's label, as over SSH.
func notificationsLabelFor(label string, n int) string {
	if n == 0 {
		return label
	}
	return fmt.Sprintf("%s (%d new)", label, n)
}

// notificationPath returns the web page n is about, or "" if its plugin
// has none.
func (s *Server) notificationPath(n notify.Notification) string {
	if s.cfg.Plugins == nil {
		return ""
	}
	k, ok := s.cfg.Plugins.NotificationKind(n.Kind)
	if !ok || k.WebPath == nil {
		return ""
	}
	rel := k.WebPath(n)
	if !strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "//") {
		return ""
	}
	id, _, _ := strings.Cut(n.Kind, ":")
	return "/p/" + id + rel
}

func (s *Server) notificationsError(w http.ResponseWriter, r *http.Request, err error) {
	LoggerFrom(r.Context()).Error("notifications", "err", err)
	s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

func (s *Server) renderNotifications(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, clearErr string) {
	ns, err := s.cfg.Notify.List(r.Context(), sess.UserID)
	if err != nil {
		s.notificationsError(w, r, err)
		return
	}
	now := s.cfg.Notify.Now()
	rows := make([]notificationRow, 0, len(ns))
	unseen := 0
	for _, n := range ns {
		if !n.Seen {
			unseen++
		}
		rows = append(rows, notificationRow{ID: strconv.FormatInt(n.ID, 10), Text: s.cfg.Notify.Describe(n),
			Age: notify.Age(n.Created, now), New: !n.Seen, Open: s.notificationPath(n) != ""})
	}
	s.render(w, r, status, "Notifications", "notifications", map[string]any{
		"Notice": notificationNotices[r.URL.Query().Get("done")], "Rows": rows, "Unseen": unseen, "CSRF": sess.CSRF,
		"Days": int(notify.MaxAge.Hours() / 24), "Keep": notify.Keep, "ClearError": clearErr,
	})
}

func (s *Server) handleNotifications(w http.ResponseWriter, r *http.Request) {
	if sess := s.member(w, r); sess != nil {
		s.renderNotifications(w, r, http.StatusOK, sess, "")
	}
}

// notificationFor loads the notification in the URL. ok is false (and the
// member sent back to the list) when it no longer exists.
func (s *Server) notificationFor(w http.ResponseWriter, r *http.Request, sess *websess.Session) (notify.Notification, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Redirect(w, r, "/notifications?done=gone", http.StatusSeeOther)
		return notify.Notification{}, false
	}
	n, err := s.cfg.Notify.Get(r.Context(), sess.UserID, id)
	switch {
	case errors.Is(err, notify.ErrNotFound):
		http.Redirect(w, r, "/notifications?done=gone", http.StatusSeeOther)
		return n, false
	case err != nil:
		s.notificationsError(w, r, err)
		return n, false
	}
	return n, true
}

// handleNotificationOpen marks a notification seen and goes to its page,
// which checks the member may still see it.
func (s *Server) handleNotificationOpen(w http.ResponseWriter, r *http.Request) {
	sess := s.member(w, r)
	if sess == nil {
		return
	}
	n, ok := s.notificationFor(w, r, sess)
	if !ok {
		return
	}
	if err := s.cfg.Notify.MarkSeen(r.Context(), sess.UserID, n.ID); err != nil {
		s.notificationsError(w, r, err)
		return
	}
	path := s.notificationPath(n)
	if path == "" {
		http.Redirect(w, r, "/notifications?done=no-web", http.StatusSeeOther)
		return
	}
	LoggerFrom(r.Context()).Debug("notification opened from the web", "kind", n.Kind)
	http.Redirect(w, r, path, http.StatusSeeOther)
}

func (s *Server) handleNotificationDelete(w http.ResponseWriter, r *http.Request) {
	sess := s.memberPost(w, r)
	if sess == nil {
		return
	}
	n, ok := s.notificationFor(w, r, sess)
	if !ok {
		return
	}
	switch err := s.cfg.Notify.Delete(r.Context(), sess.UserID, n.ID); {
	case errors.Is(err, notify.ErrNotFound):
		http.Redirect(w, r, "/notifications?done=gone", http.StatusSeeOther)
	case err != nil:
		s.notificationsError(w, r, err)
	default:
		http.Redirect(w, r, "/notifications?done=deleted", http.StatusSeeOther)
	}
}

func (s *Server) handleNotificationsSeen(w http.ResponseWriter, r *http.Request) {
	sess := s.memberPost(w, r)
	if sess == nil {
		return
	}
	if err := s.cfg.Notify.MarkSeen(r.Context(), sess.UserID); err != nil {
		s.notificationsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/notifications?done=seen", http.StatusSeeOther)
}

func (s *Server) handleNotificationsClear(w http.ResponseWriter, r *http.Request) {
	sess := s.memberPost(w, r)
	if sess == nil {
		return
	}
	if r.PostForm.Get("confirm") != "yes" {
		s.renderNotifications(w, r, http.StatusUnprocessableEntity, sess, "Tick the box to confirm, then try again.")
		return
	}
	n, err := s.cfg.Notify.DeleteAll(r.Context(), sess.UserID)
	if err != nil {
		s.notificationsError(w, r, err)
		return
	}
	LoggerFrom(r.Context()).Info("notifications deleted from the web", "count", n)
	http.Redirect(w, r, "/notifications?done=cleared", http.StatusSeeOther)
}

// notificationSettingsForm is the settings form: the SSH between-screens
// choice, then one box per kind ("kind0", "kind1", … in registration
// order).
func (s *Server) notificationSettingsForm() (*form.Form, []notify.Kind) {
	kinds := s.cfg.Notify.Kinds()
	fm := &form.Form{Fields: []form.Field{{Name: "between", Label: "Over SSH, show new notifications between screens", Kind: form.Boolean,
		Help: "When you open a menu item and when you return to the menu, never in the middle of a screen. Otherwise they wait under Notifications."}}}
	for i, k := range kinds {
		fm.Fields = append(fm.Fields, form.Field{Name: "kind" + strconv.Itoa(i), Label: "Receive notifications for: " + k.Label, Kind: form.Boolean, Help: k.Help})
	}
	return fm, kinds
}

func (s *Server) handleNotificationSettings(w http.ResponseWriter, r *http.Request) {
	sess := s.member(w, r)
	if sess == nil {
		return
	}
	cur, err := s.cfg.Prefs.Get(r.Context(), sess.UserID)
	if err != nil {
		s.notificationsError(w, r, err)
		return
	}
	on, err := s.cfg.Notify.Settings(r.Context(), sess.UserID)
	if err != nil {
		s.notificationsError(w, r, err)
		return
	}
	fm, kinds := s.notificationSettingsForm()
	vals := form.Values{"between": strconv.FormatBool(cur.Notifications)}
	for i, k := range kinds {
		vals["kind"+strconv.Itoa(i)] = strconv.FormatBool(on[k.Name])
	}
	s.render(w, r, http.StatusOK, "Notification settings", "notification-settings", map[string]any{
		"CSRF": sess.CSRF, "Fields": fieldViews(fm, vals, nil),
	})
}

func (s *Server) handleNotificationSettingsSave(w http.ResponseWriter, r *http.Request) {
	sess := s.memberPost(w, r)
	if sess == nil {
		return
	}
	fm, kinds := s.notificationSettingsForm()
	vals := formValues(fm, r)
	next := map[string]bool{}
	for i, k := range kinds {
		next[k.Name] = vals["kind"+strconv.Itoa(i)] == form.True
	}
	if err := s.cfg.Notify.SetSettings(r.Context(), sess.UserID, next); err != nil {
		s.notificationsError(w, r, err)
		return
	}
	cur, err := s.cfg.Prefs.Get(r.Context(), sess.UserID)
	if err == nil {
		cur.Notifications = vals["between"] == form.True
		err = s.cfg.Prefs.Set(r.Context(), sess.UserID, cur)
	}
	if err != nil {
		s.notificationsError(w, r, err)
		return
	}
	LoggerFrom(r.Context()).Info("notification settings changed from the web", "between_screens", cur.Notifications)
	http.Redirect(w, r, "/notifications?done=saved", http.StatusSeeOther)
}
