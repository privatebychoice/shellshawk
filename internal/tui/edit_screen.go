package tui

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// tabWidth is how many spaces Tab inserts (tabs are not stored, so text
// lines up the same everywhere).
const tabWidth = 4

var editorHelp = []string{
	"Ctrl-O  Save and finish",
	"Ctrl-X  Exit (asks whether to save if you changed anything)",
	"Ctrl-K  Cut the current line (repeat to cut several)",
	"Ctrl-U  Paste the cut lines above the cursor",
	"Ctrl-W  Find text",
	"Ctrl-P  Preview how the text will look",
	"Ctrl-G  This help",
	"Arrows, Home, End, PgUp, PgDn  Move",
	"Tab inserts four spaces. Pasting with your terminal keeps line breaks.",
}

// Edit implements UI with a nano-style full-screen editor.
func (u *Screen) Edit(ctx context.Context, r EditRequest) (string, error) {
	ed := newEditor(r.Text, true, r.max())
	ed.row, ed.col = 0, 0
	original := r.Text
	var cut [][]rune
	lastWasCut := false
	status := ""
	top := 0

	for {
		top = u.drawEditor(r, ed, status, top)
		status = ""
		ev, err := u.t.Next(ctx)
		if err != nil {
			return "", err
		}
		wasCut := false
		switch ev.Key {
		case term.KeyRune, term.KeyPaste, term.KeyEnter:
			if ed.size() >= r.max() {
				status = fmt.Sprintf("Character limit reached (%d).", r.max())
				break
			}
			switch ev.Key {
			case term.KeyRune:
				ed.insert(ev.Rune)
			case term.KeyPaste:
				ed.paste(ev.Text)
			default:
				ed.newline()
			}
		case term.KeyTab:
			for range tabWidth {
				ed.insert(' ')
			}
		case term.KeyBackspace:
			ed.backspace()
		case term.KeyDelete:
			ed.del()
		case term.KeyLeft:
			ed.left()
		case term.KeyRight:
			ed.right()
		case term.KeyUp:
			ed.up()
		case term.KeyDown:
			ed.down()
		case term.KeyHome:
			ed.home()
		case term.KeyEnd:
			ed.end()
		case term.KeyPgUp, term.KeyPgDn:
			_, rows := u.dims()
			for range max(rows-5, 1) {
				if ev.Key == term.KeyPgUp {
					ed.up()
				} else {
					ed.down()
				}
			}
		case term.KeyCtrl:
			switch ev.Rune {
			case 'a':
				ed.home()
			case 'e':
				ed.end()
			case 'o', 's':
				text := ed.value()
				if n := utf8.RuneCountInString(text); n > r.max() {
					status = fmt.Sprintf("Too long: %d characters, the limit is %d.", n, r.max())
					break
				}
				return text, nil
			case 'x':
				if ed.value() == original {
					return "", ErrCancelled
				}
				switch u.editorAsk(ctx, r, ed, top, "Save your changes? Y = yes, N = discard them, C = keep editing") {
				case 'y':
					return ed.value(), nil
				case 'n':
					return "", ErrCancelled
				}
			case 'c':
				status = "Use Ctrl-X to exit."
			case 'k':
				line := ed.lines[ed.row]
				if !lastWasCut {
					cut = nil
				}
				cut = append(cut, append([]rune{}, line...))
				if len(ed.lines) == 1 {
					ed.lines[0] = nil
				} else {
					ed.lines = append(ed.lines[:ed.row], ed.lines[ed.row+1:]...)
					ed.row = min(ed.row, len(ed.lines)-1)
				}
				ed.col = min(ed.col, len(ed.lines[ed.row]))
				wasCut = true
				status = fmt.Sprintf("Cut %d line(s).", len(cut))
			case 'u':
				if len(cut) == 0 {
					status = "Nothing to paste. Cut a line with Ctrl-K first."
					break
				}
				var paste [][]rune
				for _, l := range cut {
					paste = append(paste, append([]rune{}, l...))
				}
				ed.lines = append(ed.lines[:ed.row], append(paste, ed.lines[ed.row:]...)...)
				ed.row += len(paste)
				ed.col = 0
			case 'w':
				q := u.editorPrompt(ctx, r, ed, top, "Find: ")
				if q == "" {
					break
				}
				if !ed.find(q) {
					status = "Not found: " + q
				}
			case 'g':
				p := Page{Title: r.Title + " - help"}
				for _, l := range editorHelp {
					p.Lines = append(p.Lines, Text(l))
				}
				if err := u.Show(ctx, p); err != nil {
					return "", err
				}
			case 'p':
				if r.Preview == nil {
					status = "Preview is not available here."
					break
				}
				if err := u.Show(ctx, r.Preview(ed.value())); err != nil {
					return "", err
				}
			}
		}
		lastWasCut = wasCut
	}
}

// find moves the cursor to the next occurrence of q (case-insensitive),
// wrapping around to the start.
func (e *editor) find(q string) bool {
	needle := []rune(strings.ToLower(q))
	n := len(e.lines)
	for i := 0; i <= n; i++ {
		row := (e.row + i) % n
		line := []rune(strings.ToLower(string(e.lines[row])))
		start := 0
		if i == 0 {
			start = e.col + 1
		}
		for c := start; c+len(needle) <= len(line); c++ {
			if string(line[c:c+len(needle)]) == string(needle) {
				e.row, e.col = row, c
				return true
			}
		}
	}
	return false
}

// drawEditor renders the editor and returns the scroll offset (in wrapped
// rows) used.
func (u *Screen) drawEditor(r EditRequest, ed *editor, status string, top int) int {
	cols, rows := u.dims()
	f := u.newFrame(r.Title, "^G Help  ^O Save  ^X Exit  ^K Cut  ^U Paste  ^W Find  ^P Preview")
	width := cols - 2
	height := rows - 4 // title, status, help

	type vrow struct{ text string }
	var vrows []vrow
	curRow, curCol := 0, 0
	for li, l := range ed.lines {
		off := 0
		for {
			seg := term.Truncate(string(l[off:]), width)
			n := utf8.RuneCountInString(seg)
			if li == ed.row && ed.col >= off && (ed.col < off+n || off+n >= len(l)) {
				curRow, curCol = len(vrows), term.Width(string(l[off:ed.col]))
			}
			vrows = append(vrows, vrow{term.Sanitize(seg, false)})
			off += n
			if off >= len(l) || n == 0 {
				break
			}
		}
	}
	if curCol >= width {
		curCol = width - 1
	}
	if curRow < top {
		top = curRow
	}
	if curRow >= top+height {
		top = curRow - height + 1
	}
	for i := 0; i < height && top+i < len(vrows); i++ {
		f.put(1+i, 1, vrows[top+i].text, theme.Style{}, width)
	}
	chars := utf8.RuneCountInString(ed.value())
	info := fmt.Sprintf("Line %d of %d, %d of %d characters", ed.row+1, len(ed.lines), chars, r.max())
	if status != "" {
		info = status
	}
	f.put(rows-2, 0, " "+info, theme.Style{FG: theme.Muted}, cols)
	f.curRow, f.curCol = 1+curRow-top, 1+curCol
	_ = f.flush()
	return top
}

// editorAsk shows a question on the status line and returns the lower-case
// letter pressed (y, n or c; Esc counts as c).
func (u *Screen) editorAsk(ctx context.Context, r EditRequest, ed *editor, top int, q string) rune {
	for {
		u.drawEditor(r, ed, q, top)
		ev, err := u.t.Next(ctx)
		if err != nil {
			return 'c'
		}
		if ev.Key == term.KeyEsc || (ev.Key == term.KeyCtrl && ev.Rune == 'c') {
			return 'c'
		}
		if ev.Key == term.KeyRune {
			switch c := ev.Rune | 0x20; c {
			case 'y', 'n', 'c':
				return c
			}
		}
	}
}

// editorPrompt reads a short line of input on the status line. Esc or an
// empty answer returns "".
func (u *Screen) editorPrompt(ctx context.Context, r EditRequest, ed *editor, top int, prompt string) string {
	var buf []rune
	for {
		u.drawEditor(r, ed, prompt+string(buf), top)
		ev, err := u.t.Next(ctx)
		if err != nil {
			return ""
		}
		switch ev.Key {
		case term.KeyRune:
			if len(buf) < 200 {
				buf = append(buf, ev.Rune)
			}
		case term.KeyBackspace:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
			}
		case term.KeyEnter:
			return string(buf)
		case term.KeyEsc:
			return ""
		case term.KeyCtrl:
			if ev.Rune == 'c' {
				return ""
			}
		}
	}
}

// Edit implements UI for line mode: lines are typed one after another and
// commands on a line by themselves finish, preview or cancel.
func (u *Lines) Edit(ctx context.Context, r EditRequest) (string, error) {
	u.heading(r.Title)
	if r.Text != "" {
		n := strings.Count(r.Text, "\n") + 1
		u.println(fmt.Sprintf("Current text, %d line(s):", n))
		for _, l := range strings.Split(r.Text, "\n") {
			u.println(l)
		}
		u.println("End of current text.")
	}
	help := []string{
		"Type or paste your text. On a line by itself, type:",
		"  . (a single period) to finish",
	}
	if r.Text != "" {
		help = append(help, "  .keep to keep the current text unchanged")
	}
	if r.Preview != nil {
		help = append(help, "  .preview to hear how it will look")
	}
	help = append(help, "  .clear to start again", "  .cancel to stop without saving")
	for _, h := range help {
		u.println(h)
	}
	var lines []string
	for {
		l, err := u.readLine(ctx, "", false)
		if err != nil {
			return "", err
		}
		switch strings.TrimSpace(l) {
		case ".":
			text := strings.Join(lines, "\n")
			if n := utf8.RuneCountInString(text); n > r.max() {
				u.println(fmt.Sprintf("Error: the text is %d characters; the limit is %d. Type .clear to start again or .cancel to stop.", n, r.max()))
				continue
			}
			return text, nil
		case ".keep":
			if r.Text != "" {
				return r.Text, nil
			}
		case ".preview":
			if r.Preview != nil {
				if err := u.Show(ctx, r.Preview(strings.Join(lines, "\n"))); err != nil {
					return "", err
				}
				u.println("Continue typing, or type . to finish.")
				continue
			}
		case ".clear":
			lines = nil
			u.println("Cleared. Start typing again.")
			continue
		case ".cancel":
			return "", ErrCancelled
		}
		lines = append(lines, l)
	}
}
