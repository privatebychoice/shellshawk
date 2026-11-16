package tui

import (
	"strings"

	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// editor is a small text buffer with a cursor, used for single- and
// multi-line inputs in the full-screen UI.
type editor struct {
	lines    [][]rune
	row, col int
	multi    bool
	max      int // maximum runes in total
}

func newEditor(value string, multi bool, max int) *editor {
	e := &editor{multi: multi, max: max}
	e.set(value)
	return e
}

func (e *editor) set(v string) {
	e.lines = nil
	for _, l := range strings.Split(v, "\n") {
		e.lines = append(e.lines, []rune(l))
	}
	if !e.multi {
		e.lines = [][]rune{[]rune(strings.Join(strings.Split(v, "\n"), " "))}
	}
	e.row = len(e.lines) - 1
	e.col = len(e.lines[e.row])
}

func (e *editor) value() string {
	parts := make([]string, len(e.lines))
	for i, l := range e.lines {
		parts[i] = string(l)
	}
	return strings.Join(parts, "\n")
}

func (e *editor) size() int {
	n := len(e.lines) - 1
	for _, l := range e.lines {
		n += len(l)
	}
	return n
}

func (e *editor) insert(r rune) {
	if e.max > 0 && e.size() >= e.max {
		return
	}
	l := e.lines[e.row]
	l = append(l[:e.col], append([]rune{r}, l[e.col:]...)...)
	e.lines[e.row] = l
	e.col++
}

func (e *editor) newline() {
	if !e.multi || (e.max > 0 && e.size() >= e.max) {
		return
	}
	l := e.lines[e.row]
	head, tail := append([]rune{}, l[:e.col]...), append([]rune{}, l[e.col:]...)
	e.lines[e.row] = head
	e.lines = append(e.lines[:e.row+1], append([][]rune{tail}, e.lines[e.row+1:]...)...)
	e.row++
	e.col = 0
}

// paste inserts text; in single-line editors newlines become spaces and a
// trailing newline (common when copying a key) is dropped.
func (e *editor) paste(s string) {
	s = term.Sanitize(strings.ReplaceAll(s, "\r\n", "\n"), true)
	if !e.multi {
		s = strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", " ")
	}
	for _, r := range s {
		if r == '\n' {
			e.newline()
		} else {
			e.insert(r)
		}
	}
}

func (e *editor) backspace() {
	if e.col > 0 {
		l := e.lines[e.row]
		e.lines[e.row] = append(l[:e.col-1], l[e.col:]...)
		e.col--
		return
	}
	if e.row > 0 {
		prev := e.lines[e.row-1]
		e.col = len(prev)
		e.lines[e.row-1] = append(prev, e.lines[e.row]...)
		e.lines = append(e.lines[:e.row], e.lines[e.row+1:]...)
		e.row--
	}
}

func (e *editor) del() {
	l := e.lines[e.row]
	if e.col < len(l) {
		e.lines[e.row] = append(l[:e.col], l[e.col+1:]...)
		return
	}
	if e.row < len(e.lines)-1 {
		e.lines[e.row] = append(l, e.lines[e.row+1]...)
		e.lines = append(e.lines[:e.row+1], e.lines[e.row+2:]...)
	}
}

func (e *editor) left() {
	if e.col > 0 {
		e.col--
	} else if e.row > 0 {
		e.row--
		e.col = len(e.lines[e.row])
	}
}

func (e *editor) right() {
	if e.col < len(e.lines[e.row]) {
		e.col++
	} else if e.row < len(e.lines)-1 {
		e.row++
		e.col = 0
	}
}

// up/down report false at the first/last line so the caller can move focus.
func (e *editor) up() bool {
	if e.row == 0 {
		return false
	}
	e.row--
	e.col = min(e.col, len(e.lines[e.row]))
	return true
}

func (e *editor) down() bool {
	if e.row >= len(e.lines)-1 {
		return false
	}
	e.row++
	e.col = min(e.col, len(e.lines[e.row]))
	return true
}

func (e *editor) home()  { e.col = 0 }
func (e *editor) end()   { e.col = len(e.lines[e.row]) }
func (e *editor) clear() { e.set("") }
