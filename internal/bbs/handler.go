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
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/markdown"
	"go.privatebychoice.com/shellshawk/internal/menu"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/prefs"
	"go.privatebychoice.com/shellshawk/internal/presence"
	"go.privatebychoice.com/shellshawk/internal/privacy"
	"go.privatebychoice.com/shellshawk/internal/settings"
	"go.privatebychoice.com/shellshawk/internal/sshd"
	"go.privatebychoice.com/shellshawk/internal/tui"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Handler runs BBS sessions. It implements sshd.SessionHandler.
type Handler struct {
	Auth     *auth.Service
	Settings *settings.Service
	Grader   markdown.Grader // grades links in rendered markdown; may be nil
	Menu     *menu.Service
	Plugins  *plugin.Registry  // may be nil when no plugins are installed
	Presence *presence.Tracker // may be nil
	Privacy  *privacy.Service
	WebLogin *websess.Service // nil when the web interface is disabled
	Perms    *perm.Service
	Prefs    *prefs.Service
	Log      *slog.Logger
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
	h       *Handler
	conn    Conn
	t       *term.Terminal
	ui      tui.UI
	userID  int64 // 0 before registration
	name    string
	started time.Time // when the session began (erasure needs a fresh login)
	// unicode reports whether the current profile allows Unicode symbols.
	unicode bool
	log     *slog.Logger
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

	s := &session{h: h, conn: c, t: term.New(c.RW, c.RW, c.PTY != nil, size, resize), log: log, name: h.Settings.BBSName(ctx), started: time.Now()}
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
		return tui.Message(ctx, s.ui, s.Title("Account pending"),
			"Your account is waiting for approval by a moderator.",
			"You will be able to use the BBS once it has been approved. Please check back later.")
	case sshd.ModeMember:
		if err := s.openUserUI(ctx); err != nil {
			return err
		}
		if s.h.Presence != nil {
			defer s.h.Presence.Enter(s.userID)()
		}
		return s.home(ctx)
	}
	return errors.New("unknown session mode")
}

// Form shows fm with the BBS name in its title.
func (s *session) Form(ctx context.Context, fm *form.Form, vals form.Values, errs form.Errors) (form.Values, error) {
	titled := *fm
	titled.Title = s.Title(fm.Title)
	return s.ui.Form(ctx, &titled, vals, errs)
}

func (s *session) Title(t string) string { return s.name + " - " + t }

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
	s.unicode = st.Profile.Unicode
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
	ans, err := lines.ReadLine(ctx, "Welcome to "+s.name+". Press Enter to continue, or type s and press Enter for screen reader mode: ")
	if err != nil {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(ans), "s"), nil
}
