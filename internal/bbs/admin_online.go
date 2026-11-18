package bbs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/sessions"
	"go.privatebychoice.com/shellshawk/internal/settings"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// whoIsOnline lists every SSH connection, then every logged-in web
// session, and lets staff end one. Web session values carry a "web:"
// prefix; SSH connection values are their registry numbers.
func (s *session) whoIsOnline(ctx context.Context) error {
	title := s.Title("Who is online")
	for {
		conns, err := s.h.Sessions.List(ctx, s.userID)
		if err != nil {
			return err
		}
		webs, err := s.h.Sessions.WebSessions(ctx, s.userID)
		if err != nil {
			return err
		}
		now := time.Now()
		var items []tui.MenuItem
		for _, c := range conns {
			label := c.Describe(now)
			if c.ID == s.conn.ConnSerial {
				label += " (this connection)"
			}
			items = append(items, tui.MenuItem{Value: strconv.FormatUint(c.ID, 10), Label: label,
				Help: "SSH, connected since " + fmtTime(&c.Started)})
		}
		for _, w := range webs {
			items = append(items, tui.MenuItem{Value: "web:" + w.ID, Label: describeWeb(w, now),
				Help: "Logged in " + fmtTime(&w.Created) + ", expires " + fmtTime(&w.Expires)})
		}
		intro := fmt.Sprintf("%d SSH connection(s) open. Choose one to end it.", len(conns))
		if s.h.Sessions.HasWeb() {
			intro = fmt.Sprintf("%d SSH connection(s) and %d web session(s), SSH first. Choose one to end it.", len(conns), len(webs))
		}
		choice, err := s.ui.Choose(ctx, tui.Menu{
			Title:   title,
			Intro:   intro,
			Items:   items,
			Actions: []tui.Action{{Key: 'r', Value: "refresh", Label: "Refresh"}},
		})
		if err != nil {
			return err
		}
		switch {
		case choice == "refresh":
			continue
		case strings.HasPrefix(choice, "web:"):
			err = s.endWebSession(ctx, title, webs, strings.TrimPrefix(choice, "web:"))
		default:
			err = s.endConnection(ctx, title, conns, choice)
		}
		if err != nil {
			return err
		}
	}
}

// describeWeb is a web session's one-line summary.
func describeWeb(w sessions.WebSession, now time.Time) string {
	return w.Who() + ": web session, last active " + w.Active(now)
}

func (s *session) endConnection(ctx context.Context, title string, conns []sessions.Connection, choice string) error {
	id, _ := strconv.ParseUint(choice, 10, 64)
	if id == s.conn.ConnSerial {
		return tui.Message(ctx, s.ui, title, "This is your own connection. To leave, press q in the main menu.")
	}
	var c sessions.Connection
	for _, x := range conns {
		if x.ID == id {
			c = x
		}
	}
	ok, err := tui.Confirm(ctx, s.ui, title, "End this connection? "+c.Describe(time.Now())+". They are told it was ended by an administrator or moderator.")
	if err != nil || !ok {
		return err
	}
	msg := "The connection has been ended."
	switch err := s.h.Sessions.End(ctx, s.userID, id); {
	case errors.Is(err, sessions.ErrNotFound):
		msg = "That connection has already closed."
	case adminErrorMessage(err) != "":
		msg = "You cannot end that connection: the account has permissions you do not have."
	case err != nil:
		return err
	}
	return tui.Message(ctx, s.ui, title, msg)
}

func (s *session) endWebSession(ctx context.Context, title string, webs []sessions.WebSession, id string) error {
	var w sessions.WebSession
	for _, x := range webs {
		if x.ID == id {
			w = x
		}
	}
	ok, err := tui.Confirm(ctx, s.ui, title, "Log out this web session? "+describeWeb(w, time.Now())+". Their next page asks them to log in again.")
	if err != nil || !ok {
		return err
	}
	msg := "The web session has been logged out."
	switch err := s.h.Sessions.EndWeb(ctx, s.userID, id); {
	case errors.Is(err, sessions.ErrNotFound):
		msg = "That web session had already ended."
	case adminErrorMessage(err) != "":
		msg = "You cannot log out that web session: the account has permissions you do not have."
	case err != nil:
		return err
	}
	return tui.Message(ctx, s.ui, title, msg)
}

// connectionLimits edits the idle timeout and the per-account connection
// limit.
func (s *session) connectionLimits(ctx context.Context) error {
	intCheck := func(check func(int) error) func(string) (string, error) {
		return func(v string) (string, error) {
			n, err := strconv.Atoi(v)
			if err != nil {
				return v, err
			}
			if err := check(n); err != nil {
				return v, errors.New(strings.TrimPrefix(err.Error(), settings.ErrInvalid.Error()+": "))
			}
			return v, nil
		}
	}
	fm := &form.Form{
		Title: "Connection limits",
		Fields: []form.Field{
			{Name: "idle", Label: "Idle timeout in minutes", Kind: form.SingleLine, Subtype: form.Int, Required: true,
				Min: form.Bound(0), Max: form.Bound(settings.MaxIdleMinutes),
				Help:  fmt.Sprintf("SSH connections with no activity for this long are ended. Members are warned shortly before. 0 turns it off; otherwise %d to %d.", settings.MinIdleMinutes, settings.MaxIdleMinutes),
				Check: intCheck(settings.CheckIdleMinutes)},
			{Name: "max", Label: "Connections per account", Kind: form.SingleLine, Subtype: form.Int, Required: true,
				Min: form.Bound(0), Max: form.Bound(settings.MaxMaxPerUser),
				Help:  "How many SSH connections, terminal and file transfer together, one account may have open at once. 0 means no limit.",
				Check: intCheck(settings.CheckMaxPerUser)},
		},
	}
	cur := s.h.Settings.ConnLimits(ctx)
	v, err := s.Form(ctx, fm, form.Values{"idle": strconv.Itoa(cur.IdleMinutes), "max": strconv.Itoa(cur.MaxPerUser)}, nil)
	if err != nil {
		return err
	}
	idle, _ := strconv.Atoi(v["idle"])
	maxConns, _ := strconv.Atoi(v["max"])
	if err := s.h.Settings.SetConnLimits(ctx, s.userID, settings.ConnLimits{IdleMinutes: idle, MaxPerUser: maxConns}); err != nil {
		return err
	}
	return tui.Message(ctx, s.ui, s.Title("Connection limits"),
		"Connection limits saved. The idle timeout applies to open connections at once; the connection limit applies to new connections.")
}
