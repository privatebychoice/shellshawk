package tui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// syncBuf is a goroutine-safe output buffer.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func testForm() *form.Form {
	return &form.Form{
		Title: "Test form",
		Fields: []form.Field{
			{Name: "user", Label: "Username", Kind: form.SingleLine, Required: true, MinLen: 3, MaxLen: 32},
			{Name: "pw", Label: "Password", Kind: form.SingleLine, Subtype: form.Password, Required: true},
			{Name: "color", Label: "Colour", Kind: form.Choice, Options: []form.Option{{Value: "red", Label: "Red"}, {Value: "blue", Label: "Blue"}}},
			{Name: "news", Label: "Newsletter", Kind: form.Boolean},
			{Name: "bio", Label: "Bio", Kind: form.MultiLine},
		},
	}
}

func newTestTerm(input string, pty bool) (*term.Terminal, *syncBuf) {
	out := &syncBuf{}
	return term.New(strings.NewReader(input), out, pty, term.Size{Cols: 80, Rows: 30}, nil), out
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestLinesForm(t *testing.T) {
	tests := []struct {
		name    string
		pty     bool
		input   string
		want    form.Values
		wantOut []string
		notOut  []string
	}{
		{
			name:    "pty: echoes, hides password, re-asks invalid",
			pty:     true,
			input:   "al\ralice\rs3cret-pass\r9\r2\ryes\rline one\rline two\r.\r",
			want:    form.Values{"user": "alice", "pw": "s3cret-pass", "color": "blue", "news": "true", "bio": "line one\nline two"},
			wantOut: []string{"Field: Username (3 to 32 characters, required)", "Error: Username must be at least 3 characters.", "alice", "Error: \"9\" is not a number from 1 to 2.", "(typing is hidden)"},
			notOut:  []string{"s3cret-pass", "\x1b["},
		},
		{
			name:    "no pty: no echo, warns that password is visible",
			pty:     false,
			input:   "alice\nsecret\n\n\n.\n",
			want:    form.Values{"user": "alice", "pw": "secret", "color": "", "news": "false", "bio": ""},
			wantOut: []string{"what you type will be visible"},
		},
		{
			name:    "backspace edits",
			pty:     true,
			input:   "alicx\x7fe\rpw\r\r\r.\r",
			want:    form.Values{"user": "alice", "pw": "pw", "color": "", "news": "false", "bio": ""},
			wantOut: []string{"\b \b"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tm, out := newTestTerm(tt.input, tt.pty)
			ui := NewLines(tm, 0)
			got, err := ui.Form(ctxT(t), testForm(), nil, nil)
			if err != nil {
				t.Fatalf("Form: %v\noutput:\n%s", err, out.String())
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
			o := out.String()
			for _, s := range tt.wantOut {
				if !strings.Contains(o, s) {
					t.Errorf("output missing %q:\n%s", s, o)
				}
			}
			for _, s := range tt.notOut {
				if strings.Contains(o, s) {
					t.Errorf("output must not contain %q", s)
				}
			}
		})
	}
}

func TestLinesFormRetryOnlyErroredFields(t *testing.T) {
	tm, out := newTestTerm("bob99\r", true)
	ui := NewLines(tm, 0)
	vals := form.Values{"user": "alice", "pw": "x", "news": "false"}
	got, err := ui.Form(ctxT(t), testForm(), vals, form.Errors{"user": errors.New("that username is already taken")})
	if err != nil {
		t.Fatalf("Form: %v\n%s", err, out.String())
	}
	if got["user"] != "bob99" || got["pw"] != "x" {
		t.Errorf("values = %v", got)
	}
	if !strings.Contains(out.String(), "Error: that username is already taken") {
		t.Errorf("previous error not shown:\n%s", out.String())
	}
}

func TestLinesCancelAndChoose(t *testing.T) {
	tm, _ := newTestTerm("\x03", true)
	if _, err := NewLines(tm, 0).Form(ctxT(t), testForm(), nil, nil); !errors.Is(err, ErrCancelled) {
		t.Errorf("Ctrl-C err = %v, want ErrCancelled", err)
	}

	m := Menu{Title: "Main", Items: []MenuItem{{"a", "Alpha", "first"}, {"b", "Bravo", ""}}}
	tm, out := newTestTerm("7\r2\r", true)
	v, err := NewLines(tm, 0).Choose(ctxT(t), m)
	if err != nil || v != "b" {
		t.Errorf("Choose = %q, %v", v, err)
	}
	if o := out.String(); !strings.Contains(o, "1. Alpha. first") || !strings.Contains(o, "Error: \"7\" is not a number") || !strings.Contains(o, "Screen: Main") {
		t.Errorf("menu output:\n%s", o)
	}

	tm, _ = newTestTerm("q\r", true)
	if _, err := NewLines(tm, 0).Choose(ctxT(t), m); !errors.Is(err, ErrCancelled) {
		t.Errorf("q err = %v", err)
	}
}

func TestLinesShowPaging(t *testing.T) {
	p := Page{Title: "Long"}
	for i := range 5 {
		p.Lines = append(p.Lines, Text(strings.Repeat("x", i+1)))
	}
	p.Lines = append(p.Lines, Styled("evil\x1b[2Jtext", theme.Style{FG: theme.Error}))
	tm, out := newTestTerm("\rq\r\r", true)
	if err := NewLines(tm, 2).Show(ctxT(t), p); err != nil {
		t.Fatal(err)
	}
	o := out.String()
	if strings.Count(o, "More:") != 2 || strings.Contains(o, "xxxxx") {
		t.Errorf("paging wrong:\n%s", o)
	}
	if strings.Contains(o, "\x1b[2J") {
		t.Error("escape sequence from content reached output")
	}
}

func newTestScreen(input string) (*Screen, *syncBuf) {
	tm, out := newTestTerm(input, true)
	cat, _ := theme.Builtin()
	prof, _ := theme.LookupProfile(theme.ProfileModern)
	return NewScreen(tm, theme.Styler{Theme: cat.Get(theme.DefaultTheme), Profile: prof}), out
}

func TestScreenForm(t *testing.T) {
	paste := "\x1b[200~" + "key \x1b]0;evil\x07data\n" + "\x1b[201~"
	tests := []struct {
		name  string
		input string
		want  form.Values
	}{
		{
			name: "fill every control and submit",
			// user, Tab, password, Tab, Down + Space (Blue), Tab, Space (news), Tab,
			// bio "a" Enter "b", Ctrl-S
			input: "alice\tpw\t\x1b[B \t \ta\rb\x13",
			want:  form.Values{"user": "alice", "pw": "pw", "color": "blue", "news": "true", "bio": "a\nb"},
		},
		{
			name: "editing keys",
			// "alicx" Backspace "e", Home "x" Delete -> "xalice" -> Delete removes 'a'? No: Home puts cursor before 'a'; "x" inserts; Delete removes 'a'.
			input: "alicx\x7fe\x1b[Hx\x1b[3~\tpw\x13",
			want:  form.Values{"user": "xlice", "pw": "pw"},
		},
		{
			name:  "paste is sanitised and single-line",
			input: "abc\tpw\x1b[Z\x15" + paste + "\x13",
			want:  form.Values{"user": "key ]0;evildata", "pw": "pw"},
		},
		{
			name:  "Enter on Submit button",
			input: "alice\tpw\t\t\t\t\r",
			want:  form.Values{"user": "alice", "pw": "pw", "news": "false"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ui, out := newTestScreen(tt.input)
			got, err := ui.Form(ctxT(t), testForm(), nil, nil)
			if err != nil {
				t.Fatalf("Form: %v", err)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
			if strings.Contains(out.String(), "\x1b]0;") {
				t.Error("pasted OSC sequence reached the terminal")
			}
		})
	}
}

func TestScreenFormShowsErrorsAndCancels(t *testing.T) {
	ui, out := newTestScreen("\x13") // submit empty form, then input ends
	_, err := ui.Form(ctxT(t), testForm(), nil, nil)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("err = %v, want EOF after failed submit", err)
	}
	if !strings.Contains(out.String(), "Error: this field is required") {
		t.Error("validation error not drawn")
	}

	ui, _ = newTestScreen("abc\x1b\x1b[A") // Esc (then an arrow so ESC is not ambiguous)
	if _, err := ui.Form(ctxT(t), testForm(), nil, nil); !errors.Is(err, ErrCancelled) {
		t.Errorf("Esc err = %v", err)
	}
}

func TestScreenChooseAndShow(t *testing.T) {
	m := Menu{Title: "Main", Items: []MenuItem{{"a", "Alpha", ""}, {"b", "Bravo", ""}, {"c", "Charlie", ""}}}
	tests := []struct {
		input string
		want  string
		err   error
	}{
		{"\x1b[B\r", "b", nil},
		{"\x1b[A\r", "c", nil}, // wraps to last
		{"3", "c", nil},
		{"q", "", ErrCancelled},
	}
	for _, tt := range tests {
		ui, _ := newTestScreen(tt.input)
		v, err := ui.Choose(ctxT(t), m)
		if v != tt.want || !errors.Is(err, tt.err) {
			t.Errorf("input %q: Choose = %q, %v", tt.input, v, err)
		}
	}

	ui, out := newTestScreen("\x1b[6~\r")
	p := Page{Title: "Page"}
	for range 100 {
		p.Lines = append(p.Lines, Text("line"))
	}
	if err := ui.Show(ctxT(t), p); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "of 100)") {
		t.Error("scroll indicator missing")
	}
	if err := ui.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(out.String(), term.AltScreenOff) {
		t.Error("Close did not leave the alternate screen")
	}
}

func TestWrapLine(t *testing.T) {
	l := Line{{Text: "hello brave "}, {Text: "new world", Style: theme.Style{Bold: true}}}
	got := wrapLine(l, 11)
	var plain []string
	for _, x := range got {
		plain = append(plain, x.Plain())
	}
	want := []string{"hello brave", "new world"}
	if strings.Join(plain, "|") != strings.Join(want, "|") {
		t.Errorf("wrap = %q, want %q", plain, want)
	}
	long := wrapLine(Text(strings.Repeat("x", 25)), 10)
	if len(long) != 3 {
		t.Errorf("long word wrapped into %d lines, want 3", len(long))
	}
}

func TestEditor(t *testing.T) {
	e := newEditor("ab\ncd", true, 100)
	e.up()
	e.home()
	e.insert('X')
	e.down()
	e.end()
	e.newline()
	e.insert('Z')
	e.backspace()
	e.backspace() // joins lines
	if got := e.value(); got != "Xab\ncd" {
		t.Errorf("value = %q", got)
	}
	s := newEditor("", false, 5)
	s.paste("toolong\n")
	if s.value() != "toolo" {
		t.Errorf("max not enforced: %q", s.value())
	}
}
