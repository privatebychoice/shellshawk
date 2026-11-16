// Package bbs is the interactive BBS: the screens a user sees after logging
// in over SSH. Screens are written against tui.UI, so each works in both the
// full-screen and the line-by-line (screen reader) interface.
package bbs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/prefs"
	"go.privatebychoice.com/shellshawk/internal/sshd"
	"go.privatebychoice.com/shellshawk/internal/tui"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Handler runs BBS sessions. It implements sshd.SessionHandler.
type Handler struct {
	Name  string // BBS name shown in titles
	Auth  *auth.Service
	Perms *perm.Service
	Prefs *prefs.Service
	Log   *slog.Logger
}

var _ sshd.SessionHandler = (*Handler)(nil)

// Conn is what a session needs from the transport. It exists so sessions can
// be driven in tests without an SSH server.
type Conn struct {
	RW       io.ReadWriter
	ConnID   string
	Identity sshd.Identity
	PTY      *sshd.PTY // nil if the client did not request a terminal
	Resize   <-chan sshd.WindowSize
}

// HandleShell implements sshd.SessionHandler.
func (h *Handler) HandleShell(ctx context.Context, s *sshd.Session) {
	h.Run(ctx, Conn{RW: s, ConnID: s.ConnID, Identity: s.Identity, PTY: s.PTY, Resize: s.Resize})
}

// session is one user's connection.
type session struct {
	h      *Handler
	conn   Conn
	t      *term.Terminal
	ui     tui.UI
	userID int64 // 0 before registration
	log    *slog.Logger
}

// Run serves one session until the user leaves or the connection ends.
func (h *Handler) Run(ctx context.Context, c Conn) {
	log := h.Log.With("component", "bbs", "conn_id", c.ConnID, "mode", c.Identity.Mode)
	var size term.Size
	if c.PTY != nil {
		size = term.Size{Cols: c.PTY.Columns, Rows: c.PTY.Rows}
	}
	resize := make(chan term.Size, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case ws := <-c.Resize:
				select {
				case <-resize:
				default:
				}
				resize <- term.Size{Cols: ws.Columns, Rows: ws.Rows}
			}
		}
	}()

	s := &session{h: h, conn: c, t: term.New(c.RW, c.RW, c.PTY != nil, size, resize), log: log}
	if c.Identity.UserID != "" {
		id, err := strconv.ParseInt(c.Identity.UserID, 10, 64)
		if err != nil {
			log.Error("invalid user id in identity", "err", err)
			return
		}
		s.userID = id
		log = log.With("user_id", id)
		s.log = log
	}
	log.Info("session started", "pty", c.PTY != nil)

	err := s.run(ctx)
	if s.ui != nil {
		if cerr := s.ui.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	switch {
	case err == nil, errors.Is(err, io.EOF), errors.Is(err, context.Canceled), errors.Is(err, tui.ErrCancelled):
		log.Info("session ended")
	default:
		log.Error("session ended with error", "err", err)
	}
}

func (s *session) run(ctx context.Context) error {
	switch s.conn.Identity.Mode {
	case sshd.ModeRegister:
		return s.register(ctx)
	case sshd.ModeAddKey:
		if err := s.openUserUI(ctx); err != nil {
			return err
		}
		return s.addKeyLogin(ctx)
	case sshd.ModePending:
		if err := s.openUserUI(ctx); err != nil {
			return err
		}
		return tui.Message(ctx, s.ui, s.title("Account pending"),
			"Your account is waiting for approval by a moderator.",
			"You will be able to use the BBS once it has been approved. Please check back later.")
	case sshd.ModeMember:
		if err := s.openUserUI(ctx); err != nil {
			return err
		}
		return s.home(ctx)
	}
	return errors.New("unknown session mode")
}

// form shows fm with the BBS name in its title.
func (s *session) form(ctx context.Context, fm *form.Form, vals form.Values, errs form.Errors) (form.Values, error) {
	titled := *fm
	titled.Title = s.title(fm.Title)
	return s.ui.Form(ctx, &titled, vals, errs)
}

func (s *session) title(t string) string {
	if s.h.Name == "" {
		return t
	}
	return s.h.Name + " - " + t
}

// openUserUI opens the UI chosen in the user's preferences. Without a PTY
// only line mode is possible.
func (s *session) openUserUI(ctx context.Context) error {
	p, err := s.h.Prefs.Get(ctx, s.userID)
	if err != nil {
		return err
	}
	s.openUI(p)
	return nil
}

func (s *session) openUI(p prefs.Prefs) {
	if s.ui != nil {
		_ = s.ui.Close()
	}
	st := s.h.Prefs.Styler(p)
	if s.conn.PTY == nil || st.Profile.LineMode {
		s.ui = tui.NewLines(s.t, p.PageSize)
		return
	}
	s.ui = tui.NewScreen(s.t, st)
}

// askAccessible asks, before any screen drawing, whether to use line mode.
// It is plain text so a screen reader user can answer it.
func (s *session) askAccessible(ctx context.Context) (bool, error) {
	if s.conn.PTY == nil {
		return true, nil
	}
	lines := tui.NewLines(s.t, 0)
	name := s.h.Name
	if name == "" {
		name = "the BBS"
	}
	ans, err := lines.ReadLine(ctx, "Welcome to "+name+". Press Enter to continue, or type s and press Enter for screen reader mode: ")
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(ans), "s"), nil
}
