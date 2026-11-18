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
	"go.privatebychoice.com/shellshawk/internal/sshd"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// whoIsOnline lists every SSH connection and lets staff end one.
func (s *session) whoIsOnline(ctx context.Context) error {
	title := s.Title("Who is online")
	for {
		conns, err := s.h.Sessions.List(ctx, s.userID)
		if err != nil {
			return err
		}
		now := time.Now()
		var items []tui.MenuItem
		for _, c := range conns {
			label := describeConn(c, now)
			if c.ID == s.conn.ConnSerial {
				label += " (this connection)"
			}
			items = append(items, tui.MenuItem{Value: strconv.FormatUint(c.ID, 10), Label: label,
				Help: "Connected since " + fmtTime(&c.Started)})
		}
		choice, err := s.ui.Choose(ctx, tui.Menu{
			Title:   title,
			Intro:   fmt.Sprintf("%d connection(s) open. Choose one to end it.", len(conns)),
			Items:   items,
			Actions: []tui.Action{{Key: 'r', Value: "refresh", Label: "Refresh"}},
		})
		if err != nil {
			return err
		}
		if choice == "refresh" {
			continue
		}
		id, _ := strconv.ParseUint(choice, 10, 64)
		if id == s.conn.ConnSerial {
			if err := tui.Message(ctx, s.ui, title, "This is your own connection. To leave, press q in the main menu."); err != nil {
				return err
			}
			continue
		}
		var c sessions.Connection
		for _, x := range conns {
			if x.ID == id {
				c = x
			}
		}
		ok, err := tui.Confirm(ctx, s.ui, title, "End this connection? "+describeConn(c, time.Now())+". They are told it was ended by an administrator or moderator.")
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		msg := "The connection has been ended."
		switch err := s.h.Sessions.End(ctx, s.userID, id); {
		case errors.Is(err, sessions.ErrNotFound):
			msg = "That connection has already closed."
		case err != nil:
			if m := adminErrorMessage(err); m != "" {
				msg = "You cannot end that connection: the account has permissions you do not have."
				break
			}
			return err
		}
		if err := tui.Message(ctx, s.ui, title, msg); err != nil {
			return err
		}
	}
}

// describeConn says who a connection belongs to, what it is doing and how
// long it has been idle.
func describeConn(c sessions.Connection, now time.Time) string {
	who := c.Username
	switch {
	case c.UserID == 0:
		who = "Someone registering with an invite"
	case who == "":
		who = "Deleted account"
	}
	var uses []string
	switch sshd.Mode(c.Mode) {
	case sshd.ModePending:
		uses = append(uses, "awaiting approval")
	case sshd.ModeAddKey:
		uses = append(uses, "adding a key")
	}
	if c.Terminals > 0 {
		uses = append(uses, plural(c.Terminals, "terminal", "terminals"))
	}
	if c.Transfers > 0 {
		uses = append(uses, plural(c.Transfers, "file transfer", "file transfers"))
	}
	if len(uses) == 0 {
		uses = append(uses, "connecting")
	}
	return fmt.Sprintf("%s: %s, idle %s", who, strings.Join(uses, " and "), idleFor(now.Sub(c.LastActive)))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// idleFor describes an idle time in whole minutes.
func idleFor(d time.Duration) string {
	switch m := int(d / time.Minute); {
	case m < 1:
		return "under a minute"
	default:
		return plural(m, "minute", "minutes")
	}
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
