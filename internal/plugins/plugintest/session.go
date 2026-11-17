package plugintest

import (
	"bytes"
	"context"
	"log/slog"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/markdown"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/tui"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Session is a plugin.Session in screen-reader line mode, reading the
// member's keystrokes from a script and recording what was shown.
type Session struct {
	Env  *Env
	User int64
	Out  *bytes.Buffer
	ui   tui.UI
}

// Session returns a line-mode session for user that reads input: each
// answer ends in "\r". The input should answer every prompt; once it runs
// out, reading fails.
func (e *Env) Session(user int64, input string) *Session {
	out := &bytes.Buffer{}
	t := term.New(strings.NewReader(input), out, false, term.Size{Cols: 80, Rows: 30}, nil)
	return &Session{Env: e, User: user, Out: out, ui: tui.NewLines(t, 100)}
}

func (s *Session) UI() tui.UI            { return s.ui }
func (s *Session) UserID() int64         { return s.User }
func (s *Session) Title(t string) string { return "Test BBS - " + t }
func (s *Session) Form(ctx context.Context, fm *form.Form, v form.Values, errs form.Errors) (form.Values, error) {
	return s.ui.Form(ctx, fm, v, errs)
}
func (s *Session) Markdown(title, src string) tui.Page {
	return s.MarkdownAt(title, src, markdown.UnderTitle)
}
func (s *Session) MarkdownAt(title, src string, level int) tui.Page {
	return markdown.Page(title, src, markdown.TUIOptions{Accessible: true, HeadingLevel: level})
}
func (s *Session) Permissions(ctx context.Context) (perm.Set, error) {
	return s.Env.Perms.Permissions(ctx, s.User)
}
func (s *Session) Log() *slog.Logger { return s.Env.Log }
