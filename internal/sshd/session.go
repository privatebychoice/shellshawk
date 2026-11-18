package sshd

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/presence"
)

// Limits on client-supplied session values.
const (
	maxTermLen   = 64
	maxDimension = 1000 // columns or rows
	// Used when the client sends zero dimensions, which RFC 4254 §6.2 says
	// must be ignored (OpenSSH sends 0x0 when it cannot read its own size).
	defaultColumns = 80
	defaultRows    = 24
	maxEnvVars     = 16
	maxEnvLen      = 256 // name + value
	resizeBacklog  = 1   // only the latest size matters
)

// allowedEnv is the allowlist for "env" requests. Everything else (PATH,
// LD_PRELOAD, …) is refused; nothing is ever passed to an OS process anyway.
var allowedEnv = map[string]bool{
	"LANG": true, "LC_ALL": true, "LC_CTYPE": true, "COLORTERM": true,
}

// WindowSize is a terminal size in character cells.
type WindowSize struct {
	Columns, Rows int
}

// PTY describes the client terminal from the "pty-req" request.
type PTY struct {
	Term string
	WindowSize
}

// SFTPHandler serves the "sftp" subsystem. It is only offered to
// ModeMember logins (public key, active account).
type SFTPHandler interface {
	HandleSFTP(ctx context.Context, s *Session)
}

// SessionHandler runs the interactive BBS for one shell session. It returns
// when the user is done or ctx is cancelled (disconnect or shutdown).
type SessionHandler interface {
	HandleShell(ctx context.Context, s *Session)
}

// Session is the handler's view of a shell session. It exposes the data
// stream but not the underlying channel, so handlers cannot send SSH
// requests of their own.
type Session struct {
	Identity Identity
	ConnID   string
	// PTY is nil when the client did not request a terminal.
	PTY *PTY
	// Env holds the allowlisted environment variables the client sent.
	Env map[string]string
	// Resize delivers terminal size changes. It is never closed; select on
	// ctx.Done() as well.
	Resize <-chan WindowSize
	// ConnSerial identifies the connection in the presence.Conns registry.
	ConnSerial uint64
	// IdleWarning delivers, for interactive sessions, how long remains
	// before the connection is ended for inactivity. It is never closed.
	IdleWarning <-chan time.Duration

	ch    ssh.Channel
	touch func()
}

// Read reads user input. Anything read counts as activity.
func (s *Session) Read(p []byte) (int, error) {
	n, err := s.ch.Read(p)
	if n > 0 && s.touch != nil {
		s.touch()
	}
	return n, err
}

// Write writes output to the user's terminal.
func (s *Session) Write(p []byte) (int, error) { return s.ch.Write(p) }

// Close closes the session's channel, unblocking any pending Read.
func (s *Session) Close() error { return s.ch.Close() }

// SSH request payloads (RFC 4254 §6).
type ptyRequestMsg struct {
	Term     string
	Columns  uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
	Modes    string
}

type windowChangeMsg struct {
	Columns  uint32
	Rows     uint32
	WidthPx  uint32
	HeightPx uint32
}

type envRequestMsg struct {
	Name  string
	Value string
}

type subsystemRequestMsg struct {
	Name string
}

type exitStatusMsg struct {
	Status uint32
}

func validSize(cols, rows uint32) bool {
	return cols <= maxDimension && rows <= maxDimension
}

// applySize returns cur with any non-zero dimension from cols/rows applied.
func applySize(cur WindowSize, cols, rows uint32) WindowSize {
	if cols > 0 {
		cur.Columns = int(cols)
	}
	if rows > 0 {
		cur.Rows = int(rows)
	}
	return cur
}

func validTerm(t string) bool {
	if t == "" || len(t) > maxTermLen {
		return false
	}
	for _, r := range t {
		if r > unicode.MaxASCII || !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-_.+", r)) {
			return false
		}
	}
	return true
}

// sessionConn is what a session needs to know about its connection.
type sessionConn struct {
	id     Identity
	connID string
	conn   *presence.Conn
	warn   *idleNotifier
}

// serveSession processes requests on one "session" channel. Only pty-req,
// window-change, allowlisted env, and shell are accepted; exec, subsystems
// (sftp arrives in stage 7), x11, agent forwarding, signals and anything
// unknown are refused.
func (s *Server) serveSession(ctx context.Context, sc sessionConn, ch ssh.Channel, reqs <-chan *ssh.Request, log *slog.Logger) {
	defer ch.Close()
	id := sc.id

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		pty     *PTY
		env     = map[string]string{}
		resize  = make(chan WindowSize, resizeBacklog)
		started bool
		done    = make(chan struct{})
		wg      sync.WaitGroup
	)

	reply := func(r *ssh.Request, ok bool) {
		if r.WantReply {
			_ = r.Reply(ok, nil)
		}
	}
	refuse := func(r *ssh.Request, why string) {
		log.Info("session request refused", "type", r.Type, "reason", why)
		reply(r, false)
	}

	for {
		var r *ssh.Request
		select {
		case <-done:
			// Handler finished: report exit status and close the channel.
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: 0}))
			log.Debug("session ended")
			return
		case <-ctx.Done():
			// When the connection is ended on purpose, the handler sees the
			// reason as the context's cause; give it a moment to restore
			// the terminal and tell the member before the channel closes.
			var d *presence.Disconnect
			if started && errors.As(context.Cause(ctx), &d) {
				select {
				case <-done:
				case <-time.After(endGrace):
				}
			}
			// Shutdown or disconnect. Closing the channel unblocks a handler
			// stuck in Read; then wait for it to return.
			ch.Close()
			wg.Wait()
			return
		case req, ok := <-reqs:
			if !ok {
				// Client closed the channel; stop the handler and wait for it.
				cancel()
				ch.Close()
				wg.Wait()
				return
			}
			r = req
		}

		switch r.Type {
		case "pty-req":
			var m ptyRequestMsg
			switch {
			case started:
				refuse(r, "pty-req after shell")
			case ssh.Unmarshal(r.Payload, &m) != nil:
				refuse(r, "malformed pty-req")
			case !validTerm(m.Term) || !validSize(m.Columns, m.Rows):
				refuse(r, "invalid terminal parameters")
			default:
				pty = &PTY{Term: m.Term, WindowSize: applySize(WindowSize{Columns: defaultColumns, Rows: defaultRows}, m.Columns, m.Rows)}
				log.Debug("pty allocated", "term", m.Term, "cols", m.Columns, "rows", m.Rows)
				reply(r, true)
			}

		case "window-change":
			var m windowChangeMsg
			if ssh.Unmarshal(r.Payload, &m) != nil || !validSize(m.Columns, m.Rows) {
				refuse(r, "invalid window-change")
				continue
			}
			if m.Columns == 0 && m.Rows == 0 {
				reply(r, true) // nothing to apply
				continue
			}
			ws := applySize(WindowSize{Columns: defaultColumns, Rows: defaultRows}, m.Columns, m.Rows)
			if pty != nil {
				ws = applySize(pty.WindowSize, m.Columns, m.Rows)
				if !started {
					pty.WindowSize = ws
				}
			}
			// Latest size wins: drop a stale pending value, then send.
			select {
			case <-resize:
			default:
			}
			resize <- ws
			reply(r, true)

		case "env":
			var m envRequestMsg
			switch {
			case started:
				refuse(r, "env after shell")
			case ssh.Unmarshal(r.Payload, &m) != nil:
				refuse(r, "malformed env")
			case !allowedEnv[m.Name]:
				// Not logged at INFO: OpenSSH clients send LANG/LC_* routinely
				// and other names are harmless once refused.
				log.Debug("env refused", "name", m.Name)
				reply(r, false)
			case len(env) >= maxEnvVars || len(m.Name)+len(m.Value) > maxEnvLen:
				refuse(r, "env limits exceeded")
			default:
				env[m.Name] = m.Value
				reply(r, true)
			}

		case "shell":
			if started {
				refuse(r, "shell already started")
				continue
			}
			started = true
			reply(r, true)
			warnings, unsubscribe := sc.warn.subscribe()
			sess := &Session{Identity: id, ConnID: sc.connID, PTY: pty, Env: env, Resize: resize,
				ConnSerial: sc.conn.ID(), IdleWarning: warnings, ch: ch, touch: sc.conn.Touch}
			log.Info("shell started", "mode", id.Mode, "pty", pty != nil)
			used := sc.conn.Use(presence.UseTerminal)
			wg.Go(func() {
				defer close(done)
				defer used()
				defer unsubscribe()
				s.handler.HandleShell(ctx, sess)
			})

		case "subsystem":
			var m subsystemRequestMsg
			_ = ssh.Unmarshal(r.Payload, &m)
			switch {
			case started:
				refuse(r, "subsystem after shell")
			case m.Name != "sftp" || s.sftp == nil:
				refuse(r, "subsystem not available: "+sanitizeForLog(m.Name))
			case id.Mode != ModeMember:
				refuse(r, "sftp requires a key login to an active account")
			default:
				started = true
				reply(r, true)
				sess := &Session{Identity: id, ConnID: sc.connID, Env: env, Resize: resize,
					ConnSerial: sc.conn.ID(), ch: ch, touch: sc.conn.Touch}
				log.Info("sftp started")
				used := sc.conn.Use(presence.UseSFTP)
				wg.Go(func() {
					defer close(done)
					defer used()
					s.sftp.HandleSFTP(ctx, sess)
				})
			}

		default:
			// exec, x11-req, auth-agent-req@openssh.com, signal, break, …
			refuse(r, "request type not permitted")
		}
	}
}

// sanitizeForLog bounds and strips control characters from client-supplied
// strings before they are logged.
func sanitizeForLog(s string) string {
	const max = 64
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
