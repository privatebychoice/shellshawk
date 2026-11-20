package bbs

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/menu"
	"go.privatebychoice.com/shellshawk/internal/notify"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// notificationsTarget is the Notifications menu item. Opening it shows no
// new-notification screen: the member is about to see the list anyway.
const notificationsTarget = menu.TargetNotifications

// maxNotices is how many new notifications are listed between screens;
// the rest are under Notifications.
const maxNotices = 10

// notices shows the member's new notifications between screens (when
// opening a menu item and when returning to the menu), in both modes,
// unless they turned it off. Each is marked as seen once listed. Choosing
// one opens it; q continues. Only the session ending is an error.
func (s *session) notices(ctx context.Context) error {
	if s.h.Notify == nil || s.ui == nil {
		return nil
	}
	p, err := s.h.Prefs.Get(ctx, s.userID)
	if err != nil {
		s.log.Error("load preferences for notifications", "err", err)
		return nil
	}
	if !p.Notifications {
		return nil
	}
	ns, err := s.h.Notify.Unseen(ctx, s.userID)
	if err != nil {
		s.log.Error("load new notifications", "err", err)
		return nil
	}
	if len(ns) == 0 {
		return nil
	}
	if err := s.h.Notify.MarkSeen(ctx, s.userID); err != nil {
		s.log.Error("mark notifications seen", "err", err)
	}
	intro := fmt.Sprintf("You have %d new notification(s). Choose one to open it.", len(ns))
	if len(ns) > maxNotices {
		intro = fmt.Sprintf("You have %d new notifications; the latest %d are below and the rest are under Notifications.", len(ns), maxNotices)
		ns = ns[len(ns)-maxNotices:]
	}
	byID := map[string]notify.Notification{}
	var items []tui.MenuItem
	for _, n := range ns {
		id := strconv.FormatInt(n.ID, 10)
		byID[id] = n
		items = append(items, tui.MenuItem{Value: id, Label: s.h.Notify.Describe(n), Help: notify.Age(n.Created, s.h.Notify.Now())})
	}
	s.log.Debug("new notifications shown", "count", len(ns))
	choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("New notifications"), Intro: intro, Items: items, Back: "Continue"})
	switch {
	case errors.Is(err, tui.ErrCancelled):
		return nil
	case err != nil:
		if sessionEnded(err) {
			return err
		}
		s.log.Error("show new notifications", "err", err)
		return nil
	}
	return s.openNotification(ctx, byID[choice])
}

// newCount returns how many notifications the member has not seen; 0 on
// failure, which is logged.
func (s *session) newCount(ctx context.Context) int {
	if s.h.Notify == nil {
		return 0
	}
	n, err := s.h.Notify.CountUnseen(ctx, s.userID)
	if err != nil {
		s.log.Error("count new notifications", "err", err)
	}
	return n
}

// openable reports whether n's plugin can open it, and the label for doing so.
func (s *session) openable(n notify.Notification) (label string, ok bool) {
	if s.h.Plugins == nil {
		return "", false
	}
	k, ok := s.h.Plugins.NotificationKind(n.Kind)
	if !ok || k.Open == nil {
		return "", false
	}
	if k.OpenLabel == "" {
		return "Open", true
	}
	return k.OpenLabel, true
}

// openNotification hands n to the plugin that sent it. Plugin failures are
// logged and reported without ending the session.
func (s *session) openNotification(ctx context.Context, n notify.Notification) error {
	if _, ok := s.openable(n); !ok {
		return nil
	}
	k, _ := s.h.Plugins.NotificationKind(n.Kind)
	ps := &pluginSession{session: s, log: s.log.With("notification", n.Kind)}
	err := safeRun(func() error { return k.Open(ctx, ps, n) })
	switch {
	case err == nil, errors.Is(err, tui.ErrCancelled):
		return nil
	case sessionEnded(err):
		return err
	}
	ps.log.Error("opening a notification failed", "err", err)
	return tui.Message(ctx, s.ui, s.Title("Error"), "Sorry, something went wrong. The problem has been logged.")
}

// notifications is the Notifications menu item: every notification kept,
// newest first.
func (s *session) notifications(ctx context.Context) error {
	for {
		ns, err := s.h.Notify.List(ctx, s.userID)
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		unseen := 0
		for _, n := range ns {
			label := s.h.Notify.Describe(n)
			if !n.Seen {
				label = "New: " + label
				unseen++
			}
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(n.ID, 10), Label: label, Help: notify.Age(n.Created, s.h.Notify.Now())})
		}
		intro := fmt.Sprintf("Notifications are kept for %d days, at most %d.", int(notify.MaxAge.Hours()/24), notify.Keep)
		if len(ns) == 0 {
			intro = "You have no notifications. " + intro
		}
		actions := []tui.Action{{Key: 's', Value: "settings", Label: "Notification settings"}}
		if unseen > 0 {
			actions = append(actions, tui.Action{Key: 'm', Value: "seen", Label: "Mark all as seen"})
		}
		if len(ns) > 0 {
			actions = append(actions, tui.Action{Key: 'd', Value: "clear", Label: "Delete all"})
		}
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Notifications"), Intro: intro, Items: items, Actions: actions})
		if err != nil {
			return err
		}
		switch choice {
		case "settings":
			err = s.notificationSettings(ctx)
		case "seen":
			err = s.h.Notify.MarkSeen(ctx, s.userID)
		case "clear":
			var yes bool
			if yes, err = tui.Confirm(ctx, s.ui, s.Title("Notifications"), fmt.Sprintf("Delete all %d notification(s)?", len(ns))); err == nil && yes {
				_, err = s.h.Notify.DeleteAll(ctx, s.userID)
			}
		default:
			id, _ := strconv.ParseInt(choice, 10, 64)
			err = s.notification(ctx, id)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) && !errors.Is(err, notify.ErrNotFound) {
			return err
		}
	}
}

// notification shows one notification, marking it seen.
func (s *session) notification(ctx context.Context, id int64) error {
	n, err := s.h.Notify.Get(ctx, s.userID, id)
	if err != nil {
		return err
	}
	if err := s.h.Notify.MarkSeen(ctx, s.userID, id); err != nil {
		return err
	}
	var items []tui.MenuItem
	if label, ok := s.openable(n); ok {
		items = append(items, tui.MenuItem{Value: "open", Label: label})
	}
	items = append(items, tui.MenuItem{Value: "delete", Label: "Delete this notification"})
	choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Notification"),
		Intro: s.h.Notify.Describe(n) + ". " + notify.Age(n.Created, s.h.Notify.Now()) + ".", Items: items})
	if err != nil {
		return err
	}
	if choice == "delete" {
		return s.h.Notify.Delete(ctx, s.userID, id)
	}
	return s.openNotification(ctx, n)
}

// notificationSettings chooses whether new notifications are shown between
// screens and which kinds the member receives.
func (s *session) notificationSettings(ctx context.Context) error {
	cur, err := s.h.Prefs.Get(ctx, s.userID)
	if err != nil {
		return err
	}
	on, err := s.h.Notify.Settings(ctx, s.userID)
	if err != nil {
		return err
	}
	kinds := s.h.Notify.Kinds()
	fm := &form.Form{Title: "Notification settings", Fields: []form.Field{{
		Name: "between", Label: "Show new notifications between screens", Kind: form.Boolean,
		Help: "When you open a menu item and when you return to the menu, never in the middle of a screen. Otherwise they wait under Notifications.",
	}}}
	vals := form.Values{"between": strconv.FormatBool(cur.Notifications)}
	for i, k := range kinds {
		name := "kind" + strconv.Itoa(i)
		fm.Fields = append(fm.Fields, form.Field{Name: name, Label: "Receive notifications for: " + k.Label, Kind: form.Boolean, Help: k.Help})
		vals[name] = strconv.FormatBool(on[k.Name])
	}
	v, err := s.Form(ctx, fm, vals, nil)
	if err != nil {
		return err
	}
	next := map[string]bool{}
	for i, k := range kinds {
		next[k.Name] = v["kind"+strconv.Itoa(i)] == form.True
	}
	if err := s.h.Notify.SetSettings(ctx, s.userID, next); err != nil {
		return err
	}
	cur.Notifications = v["between"] == form.True
	if err := s.h.Prefs.Set(ctx, s.userID, cur); err != nil {
		return err
	}
	s.log.Info("notification settings changed", "between_screens", cur.Notifications)
	return tui.Message(ctx, s.ui, s.Title("Notification settings"), "Your notification settings have been saved.")
}
