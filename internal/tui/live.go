package tui

import (
	"context"
	"strings"
	"sync"

	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// maxScrollback bounds the lines a live view keeps.
const maxScrollback = 1000

// inbox moves lines from a LiveRequest's Incoming channel into a buffer
// and wakes the UI loop, which may be blocked reading the keyboard.
type inbox struct {
	mu     sync.Mutex
	lines  []Line
	closed bool
	wake   chan struct{}
}

func startInbox(ctx context.Context, in <-chan Line) *inbox {
	ib := &inbox{wake: make(chan struct{}, 1)}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case l, ok := <-in:
				ib.mu.Lock()
				if ok {
					ib.lines = append(ib.lines, l)
				} else {
					ib.closed = true
				}
				ib.mu.Unlock()
				select {
				case ib.wake <- struct{}{}:
				default:
				}
				if !ok {
					return
				}
			}
		}
	}()
	return ib
}

// take returns pending lines and whether the source has closed.
func (ib *inbox) take() ([]Line, bool) {
	ib.mu.Lock()
	defer ib.mu.Unlock()
	l := ib.lines
	ib.lines = nil
	return l, ib.closed
}

// Live implements UI: a scrolling conversation above an input line.
func (u *Screen) Live(ctx context.Context, r LiveRequest) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ib := startInbox(ctx, r.Incoming)
	lines := append([]Line(nil), r.History...)
	ed := newEditor("", false, r.max())
	scroll := 0 // rows scrolled up from the bottom

	add := func(ls ...Line) {
		lines = append(lines, ls...)
		if over := len(lines) - maxScrollback; over > 0 {
			lines = lines[over:]
		}
	}
	for {
		more, closed := ib.take()
		add(more...)
		u.drawLive(r.Title, lines, ed, scroll)
		if closed {
			return nil
		}
		ev, woke, err := u.t.NextWake(ctx, ib.wake)
		if err != nil {
			return err
		}
		if woke {
			continue
		}
		_, rows := u.dims()
		switch ev.Key {
		case term.KeyRune:
			ed.insert(ev.Rune)
		case term.KeyPaste:
			ed.paste(ev.Text)
		case term.KeyBackspace:
			ed.backspace()
		case term.KeyDelete:
			ed.del()
		case term.KeyLeft:
			ed.left()
		case term.KeyRight:
			ed.right()
		case term.KeyHome:
			ed.home()
		case term.KeyEnd:
			ed.end()
		case term.KeyPgUp:
			scroll += rows / 2
		case term.KeyPgDn:
			scroll = max(0, scroll-rows/2)
		case term.KeyEsc:
			return nil
		case term.KeyCtrl:
			switch ev.Rune {
			case 'c':
				return nil
			case 'u':
				ed.clear()
			case 'a':
				ed.home()
			case 'e':
				ed.end()
			}
		case term.KeyEnter:
			text := strings.TrimSpace(ed.value())
			ed.clear()
			if text == "" {
				continue
			}
			scroll = 0
			feedback, leave := r.Submit(text)
			add(feedback...)
			if leave {
				return nil
			}
		}
	}
}

func (u *Screen) drawLive(title string, lines []Line, ed *editor, scroll int) {
	cols, rows := u.dims()
	help := "Enter send  /help commands  PgUp/PgDn scroll  Esc leave"
	f := u.newFrame(title, help)
	width := cols - 2
	var wrapped []Line
	for _, l := range lines {
		wrapped = append(wrapped, WrapLine(l, width)...)
	}
	height := rows - 4 // title, input, help, one spacer
	scroll = min(scroll, max(0, len(wrapped)-height))
	end := len(wrapped) - scroll
	start := max(0, end-height)
	for i, l := range wrapped[start:end] {
		f.putLine(1+i, 1, l)
	}
	if scroll > 0 {
		f.put(rows-3, 1, "(scrolled up: PgDn to return)", theme.Style{FG: theme.Muted}, width)
	}
	prompt := "> "
	text, cur := inputText(ed, width-len(prompt))
	f.put(rows-2, 0, prompt+text, theme.Style{FG: theme.InputFG, BG: theme.InputBG}, cols)
	f.curRow, f.curCol = rows-2, len(prompt)+cur
	_ = f.flush()
}

// inputText is the visible window of a single-line editor and the cursor's
// cell offset within it.
func inputText(ed *editor, width int) (string, int) {
	line := ed.lines[0]
	start := 0
	for term.Width(string(line[start:ed.col])) >= width {
		start++
	}
	return term.Truncate(term.Sanitize(string(line[start:]), false), width), term.Width(string(line[start:ed.col]))
}

// Live implements UI for line mode. Incoming lines are printed as they
// arrive; if the member was part-way through typing, their text is shown
// again on a new prompt so nothing is lost. No escape sequences are used.
func (u *Lines) Live(ctx context.Context, r LiveRequest) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ib := startInbox(ctx, r.Incoming)
	u.heading(r.Title)
	u.println("Type a message and press Enter. Type /help for commands, or /quit to leave.")
	for _, l := range r.History {
		u.println(l.Plain())
	}
	const prompt = "> "
	u.t.WriteString(prompt)
	var buf []rune
	echo := u.echo()
	for {
		more, closed := ib.take()
		for _, l := range more {
			text := term.Sanitize(l.Plain(), false)
			if echo && len(buf) == 0 {
				// Overwrite the bare prompt.
				u.t.WriteString("\r" + text + strings.Repeat(" ", max(0, len(prompt)-term.Width(text))) + "\r\n" + prompt)
			} else if echo {
				u.t.WriteString("\r\n" + text + "\r\n" + prompt + string(buf))
			} else {
				u.t.WriteString(text + "\r\n")
			}
		}
		if err := u.t.Flush(); err != nil {
			return err
		}
		if closed {
			u.t.WriteString("\r\n")
			return u.t.Flush()
		}
		ev, woke, err := u.t.NextWake(ctx, ib.wake)
		if err != nil {
			return err
		}
		if woke {
			continue
		}
		switch ev.Key {
		case term.KeyRune:
			if len(buf) < r.max() {
				buf = append(buf, ev.Rune)
				if echo {
					u.t.WriteString(string(ev.Rune))
				}
			}
		case term.KeyBackspace:
			if n := len(buf); n > 0 {
				w := term.RuneWidth(buf[n-1])
				buf = buf[:n-1]
				if echo && w > 0 {
					u.t.WriteString(strings.Repeat("\b", w) + strings.Repeat(" ", w) + strings.Repeat("\b", w))
				}
			}
		case term.KeyEsc:
			u.t.WriteString("\r\n")
			return u.t.Flush()
		case term.KeyCtrl:
			if ev.Rune == 'c' {
				u.t.WriteString("\r\n")
				return u.t.Flush()
			}
		case term.KeyEnter:
			if echo {
				u.t.WriteString("\r\n")
			}
			text := strings.TrimSpace(string(buf))
			buf = buf[:0]
			if text != "" {
				feedback, leave := r.Submit(text)
				for _, l := range feedback {
					u.println(l.Plain())
				}
				if leave {
					return u.t.Flush()
				}
			}
			u.t.WriteString(prompt)
		}
		if err := u.t.Flush(); err != nil {
			return err
		}
	}
}
