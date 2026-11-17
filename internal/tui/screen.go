package tui

import (
	"context"
	"fmt"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// Screen is the full-screen UI. Every event redraws the whole screen, which
// keeps the code simple and is cheap at terminal sizes.
type Screen struct {
	t  *term.Terminal
	st theme.Styler
}

// Minimum usable size; smaller terminals are drawn as if this size.
const minCols, minRows = 30, 8

// NewScreen switches the terminal to the alternate screen.
func NewScreen(t *term.Terminal, st theme.Styler) *Screen {
	t.WriteString(term.AltScreenOn + term.BracketPasteOn + term.CursorHide)
	return &Screen{t: t, st: st}
}

// LineMode implements UI.
func (u *Screen) LineMode() bool { return false }

// Close implements UI: restores the normal screen.
func (u *Screen) Close() error {
	u.t.WriteString(theme.Reset + term.BracketPasteOff + term.CursorShow + term.AltScreenOff)
	return u.t.Flush()
}

func (u *Screen) dims() (cols, rows int) {
	s := u.t.Size()
	return max(s.Cols, minCols), max(s.Rows, minRows)
}

func (u *Screen) sym(unicode, ascii string) string {
	if u.st.Profile.Unicode {
		return unicode
	}
	return ascii
}

// ---- drawing ------------------------------------------------------------

// frame accumulates one full redraw.
type frame struct {
	u          *Screen
	cols, rows int
	curRow     int // cursor position for text input; -1 = hidden
	curCol     int
}

func (u *Screen) newFrame(title, help string) *frame {
	cols, rows := u.dims()
	f := &frame{u: u, cols: cols, rows: rows, curRow: -1}
	u.t.WriteString(u.st.SGR(theme.Style{}) + term.CursorHide + term.ClearScreen)
	f.put(0, 0, " "+title, theme.Style{FG: theme.TitleFG, BG: theme.TitleBG, Bold: true}, cols)
	f.put(rows-1, 0, " "+help, theme.Style{FG: theme.TitleFG, BG: theme.TitleBG}, cols)
	return f
}

// bodyTop/bodyRows are the rows available between title and help bars.
func (f *frame) bodyTop() int  { return 2 }
func (f *frame) bodyRows() int { return f.rows - 4 }

// put writes sanitised text at row/col in style, padded to width cells.
func (f *frame) put(row, col int, text string, st theme.Style, width int) {
	f.u.t.WriteString(term.MoveTo(row, col) + f.u.st.SGR(st) + term.Pad(term.Sanitize(text, false), width) + f.u.st.SGR(theme.Style{}))
}

// putLine writes a line of spans at row, truncated to the screen width.
func (f *frame) putLine(row, col int, l Line) {
	f.u.t.WriteString(term.MoveTo(row, col))
	used := col
	last := ""
	for _, s := range l {
		txt := term.Truncate(term.Sanitize(s.Text, false), f.cols-used)
		if txt == "" {
			continue
		}
		sgr := s.SGR
		if sgr == "" {
			sgr = f.u.st.SGR(s.Style)
		}
		if sgr != last { // only emit a style change when the style changes
			f.u.t.WriteString(sgr)
			last = sgr
		}
		f.u.t.WriteString(txt)
		used += term.Width(txt)
	}
	f.u.t.WriteString(f.u.st.SGR(theme.Style{}))
}

func (f *frame) flush() error {
	if f.curRow >= 0 {
		f.u.t.WriteString(term.MoveTo(f.curRow, f.curCol) + term.CursorShow)
	}
	return f.u.t.Flush()
}

// WrapLine wraps a styled line to width, breaking at spaces.
func WrapLine(l Line, width int) []Line {
	var out []Line
	var cur Line
	used := 0
	flush := func() { out = append(out, cur); cur, used = nil, 0 }
	for _, s := range l {
		for i, word := range strings.Split(term.Sanitize(s.Text, false), " ") {
			piece := word
			if i > 0 {
				piece = " " + word
			}
			w := term.Width(piece)
			if used > 0 && used+w > width {
				flush()
				piece = word
				w = term.Width(word)
			}
			for w > width { // hard-break very long words
				head := term.Truncate(piece, width-used)
				if head == "" {
					flush()
					continue
				}
				cur = append(cur, Span{Text: head, Style: s.Style, SGR: s.SGR})
				flush()
				piece = piece[len(head):]
				w = term.Width(piece)
			}
			cur = append(cur, Span{Text: piece, Style: s.Style, SGR: s.SGR})
			used += w
		}
	}
	if len(cur) > 0 || len(out) == 0 {
		out = append(out, cur)
	}
	return out
}

// ---- Show -----------------------------------------------------------------

// Show implements UI.
func (u *Screen) Show(ctx context.Context, p Page) error {
	top := 0
	for {
		cols, _ := u.dims()
		var lines []Line
		for _, l := range p.Lines {
			lines = append(lines, WrapLine(l, cols-2)...)
		}
		help := "Enter close"
		f := u.newFrame(p.Title, "")
		body := f.bodyRows()
		maxTop := max(0, len(lines)-body)
		top = min(max(top, 0), maxTop)
		if maxTop > 0 {
			help = fmt.Sprintf("%s/%s scroll  PgUp/PgDn page  Enter close  (%d-%d of %d)",
				u.sym("↑", "Up"), u.sym("↓", "Down"), top+1, min(top+body, len(lines)), len(lines))
		}
		f.put(f.rows-1, 0, " "+help, theme.Style{FG: theme.TitleFG, BG: theme.TitleBG}, f.cols)
		for i := 0; i < body && top+i < len(lines); i++ {
			f.putLine(f.bodyTop()+i, 1, lines[top+i])
		}
		if err := f.flush(); err != nil {
			return err
		}

		ev, err := u.t.Next(ctx)
		if err != nil {
			return err
		}
		switch ev.Key {
		case term.KeyUp:
			top--
		case term.KeyDown:
			top++
		case term.KeyPgUp:
			top -= body
		case term.KeyPgDn:
			top += body
		case term.KeyHome:
			top = 0
		case term.KeyEnd:
			top = maxTop
		case term.KeyEnter, term.KeyEsc:
			return nil
		case term.KeyRune:
			switch ev.Rune {
			case 'q', 'Q':
				return nil
			case ' ':
				if top >= maxTop {
					return nil
				}
				top += body
			}
		case term.KeyCtrl:
			if ev.Rune == 'c' {
				return nil
			}
		}
	}
}

// ---- Choose ---------------------------------------------------------------

// Choose implements UI. Items are numbered; actions are shown on a line of
// their own above the list and chosen with their letter; q and Esc go back.
func (u *Screen) Choose(ctx context.Context, m Menu) (string, error) {
	if err := m.check(); err != nil {
		return "", err
	}
	sel, top := 0, 0
	for {
		cols, _ := u.dims()
		f := u.newFrame(m.Title, fmt.Sprintf("%s/%s move  Enter select  1-9 shortcut  Esc back", u.sym("↑", "Up"), u.sym("↓", "Down")))
		row := f.bodyTop()
		if m.Intro != "" {
			for _, l := range WrapLine(Text(m.Intro), cols-2) {
				f.putLine(row, 1, l)
				row++
			}
			row++
		}
		for _, l := range WrapLine(u.actionLine(m), cols-2) {
			f.putLine(row, 1, l)
			row++
		}
		row++
		avail := f.bodyRows() - (row - f.bodyTop()) - 2 // keep room for item help
		avail = max(avail, 1)
		if sel < top {
			top = sel
		}
		if sel >= top+avail {
			top = sel - avail + 1
		}
		if len(m.Items) > avail {
			// Longer than the screen: page keys and where the view is.
			end := min(top+avail, len(m.Items))
			where := fmt.Sprintf("(%d-%d of %d", top+1, end, len(m.Items))
			switch {
			case top > 0 && end < len(m.Items):
				where += ", more above and below)"
			case top > 0:
				where += ", more above)"
			default:
				where += ", more below)"
			}
			// Position first: on a narrow screen the bar is cut at the end.
			help := fmt.Sprintf("%s  %s/%s move  PgUp/PgDn page  Enter select  1-9 shortcut  Esc back", where, u.sym("↑", "Up"), u.sym("↓", "Down"))
			f.put(f.rows-1, 0, " "+help, theme.Style{FG: theme.TitleFG, BG: theme.TitleBG}, f.cols)
		}
		marker := u.sym("▶ ", "> ")
		for i := top; i < len(m.Items) && i < top+avail; i++ {
			label := fmt.Sprintf("%d. %s", i+1, m.Items[i].Label)
			if i == sel {
				f.put(row, 1, marker+label, theme.Style{FG: theme.FocusFG, BG: theme.FocusBG, Bold: true}, cols-2)
			} else {
				f.put(row, 1, "  "+label, theme.Style{}, cols-2)
			}
			row++
		}
		if len(m.Items) > 0 {
			if h := m.Items[sel].Help; h != "" {
				f.put(f.rows-3, 1, h, theme.Style{FG: theme.Muted}, cols-2)
			}
		}
		if err := f.flush(); err != nil {
			return "", err
		}

		ev, err := u.t.Next(ctx)
		if err != nil {
			return "", err
		}
		n := len(m.Items)
		switch ev.Key {
		case term.KeyUp, term.KeyBacktab:
			if n > 0 {
				sel = (sel - 1 + n) % n
			}
		case term.KeyDown, term.KeyTab:
			if n > 0 {
				sel = (sel + 1) % n
			}
		case term.KeyPgUp:
			sel = max(sel-avail, 0)
		case term.KeyPgDn:
			sel = max(min(sel+avail, n-1), 0)
		case term.KeyHome:
			sel = 0
		case term.KeyEnd:
			sel = max(n-1, 0)
		case term.KeyEnter:
			if n > 0 {
				return m.Items[sel].Value, nil
			}
		case term.KeyEsc:
			return "", ErrCancelled
		case term.KeyCtrl:
			if ev.Rune == 'c' {
				return "", ErrCancelled
			}
		case term.KeyRune:
			if ev.Rune >= '1' && ev.Rune <= '9' {
				if i := int(ev.Rune - '1'); i < n {
					return m.Items[i].Value, nil
				}
			}
			if ev.Rune == BackKey || ev.Rune == 'Q' {
				return "", ErrCancelled
			}
			if a, ok := m.action(string(ev.Rune)); ok {
				return a.Value, nil
			}
		}
	}
}

// actionLine lists the menu's letter keys, ending with q to go back:
// "n Start a thread · d Delete this conference · q Back".
func (u *Screen) actionLine(m Menu) Line {
	key := theme.Style{FG: theme.Accent, Bold: true}
	sep := u.sym("  ·  ", "  |  ")
	var l Line
	add := func(k rune, label string) {
		if len(l) > 0 {
			l = append(l, Span{Text: sep, Style: theme.Style{FG: theme.Muted}})
		}
		l = append(l, Span{Text: string(k), Style: key}, Span{Text: " " + label})
	}
	for _, a := range m.Actions {
		add(a.Key, a.Label)
	}
	add(BackKey, m.backLabel())
	return l
}

// ---- Form -----------------------------------------------------------------

type fieldState struct {
	f   *form.Field
	ed  *editor // text fields
	opt int     // choice cursor
	val string  // choice/boolean value
	err error
}

func (fs *fieldState) value() string {
	if fs.ed != nil {
		return fs.ed.value()
	}
	return fs.val
}

const multiLineRows = 4

// Form implements UI.
func (u *Screen) Form(ctx context.Context, fm *form.Form, values form.Values, errs form.Errors) (form.Values, error) {
	states := make([]*fieldState, len(fm.Fields))
	for i := range fm.Fields {
		f := &fm.Fields[i]
		fs := &fieldState{f: f, err: errs[f.Name]}
		switch f.Kind {
		case form.SingleLine, form.MultiLine:
			v := values[f.Name]
			if f.Subtype == form.Password {
				v = "" // never pre-fill secrets
			}
			fs.ed = newEditor(v, f.Kind == form.MultiLine, maxInputLen)
		case form.Choice, form.Boolean:
			fs.val = values[f.Name]
		}
		states[i] = fs
	}
	submit, cancel := len(states), len(states)+1
	focus := 0
	for i, fs := range states {
		if fs.err != nil {
			focus = i
			break
		}
	}
	scroll := 0

	validateOne := func(i int) {
		if i < len(states) {
			_, states[i].err = states[i].f.Validate(states[i].value())
		}
	}
	move := func(to int) {
		validateOne(focus)
		focus = (to + len(states) + 2) % (len(states) + 2)
	}

	for {
		scroll = u.drawForm(fm, states, focus, scroll)

		ev, err := u.t.Next(ctx)
		if err != nil {
			return nil, err
		}
		var fs *fieldState
		if focus < len(states) {
			fs = states[focus]
		}

		// Keys that behave the same everywhere.
		switch {
		case ev.Key == term.KeyTab:
			move(focus + 1)
			continue
		case ev.Key == term.KeyBacktab:
			move(focus - 1)
			continue
		case ev.Key == term.KeyEsc, ev.Key == term.KeyCtrl && ev.Rune == 'c':
			return nil, ErrCancelled
		case ev.Key == term.KeyCtrl && ev.Rune == 's':
			focus = submit
			ev = term.Event{Key: term.KeyEnter}
		}

		if focus >= len(states) {
			switch ev.Key {
			case term.KeyLeft, term.KeyRight:
				focus = submit + cancel - focus
			case term.KeyUp:
				move(focus - 1)
			case term.KeyDown:
				move(focus + 1)
			case term.KeyEnter:
				if focus == cancel {
					return nil, ErrCancelled
				}
				vals := form.Values{}
				for _, s := range states {
					vals[s.f.Name] = s.value()
				}
				out, verrs := fm.Validate(vals)
				if len(verrs) == 0 {
					return out, nil
				}
				first := -1
				for i, s := range states {
					s.err = verrs[s.f.Name]
					if s.err != nil && first < 0 {
						first = i
					}
				}
				focus = first
			}
			continue
		}

		switch fs.f.Kind {
		case form.SingleLine, form.MultiLine:
			u.editKey(fs, ev, &focus, move)
		case form.Choice:
			opts := fs.f.Options
			switch ev.Key {
			case term.KeyUp:
				if fs.opt > 0 {
					fs.opt--
				} else {
					move(focus - 1)
				}
			case term.KeyDown:
				if fs.opt < len(opts)-1 {
					fs.opt++
				} else {
					move(focus + 1)
				}
			case term.KeyEnter, term.KeyRune:
				if ev.Key == term.KeyRune && ev.Rune != ' ' {
					break
				}
				v := opts[fs.opt].Value
				if fs.f.Multi {
					fs.val = toggleChoice(fs.val, v)
				} else {
					fs.val = v
				}
				fs.err = nil
				if ev.Key == term.KeyEnter && !fs.f.Multi {
					move(focus + 1)
				}
			}
		case form.Boolean:
			switch ev.Key {
			case term.KeyUp:
				move(focus - 1)
			case term.KeyDown, term.KeyEnter:
				move(focus + 1)
			case term.KeyRune:
				if ev.Rune == ' ' {
					if fs.val == form.True {
						fs.val = form.False
					} else {
						fs.val = form.True
					}
				}
			}
		}
	}
}

func (u *Screen) editKey(fs *fieldState, ev term.Event, focus *int, move func(int)) {
	ed := fs.ed
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
	case term.KeyUp:
		if !ed.multi || !ed.up() {
			move(*focus - 1)
		}
	case term.KeyDown:
		if !ed.multi || !ed.down() {
			move(*focus + 1)
		}
	case term.KeyEnter:
		if ed.multi {
			ed.newline()
		} else {
			move(*focus + 1)
		}
	case term.KeyCtrl:
		switch ev.Rune {
		case 'u':
			ed.clear()
		case 'a':
			ed.home()
		case 'e':
			ed.end()
		}
	}
}

func toggleChoice(cur, v string) string {
	var out []string
	found := false
	for _, c := range strings.Split(cur, ",") {
		if c == "" {
			continue
		}
		if c == v {
			found = true
			continue
		}
		out = append(out, c)
	}
	if !found {
		out = append(out, v)
	}
	return strings.Join(out, ",")
}

// formRow is one rendered row of the form, before scrolling.
type formRow struct {
	draw   func(f *frame, row int)
	field  int // owning field index (or submit row)
	cursor int // column of the text cursor on this row, or -1
}

// drawForm renders the form and returns the scroll offset used.
func (u *Screen) drawForm(fm *form.Form, states []*fieldState, focus, scroll int) int {
	cols, _ := u.dims()
	inner := cols - 4
	help := "Tab next  Shift-Tab back  Ctrl-S submit  Esc cancel"
	f := u.newFrame(fm.Title, help)
	marker := u.sym("▶ ", "> ")
	var rows []formRow
	add := func(field, cursor int, d func(f *frame, row int)) {
		rows = append(rows, formRow{draw: d, field: field, cursor: cursor})
	}

	if fm.Intro != "" {
		for _, l := range WrapLine(Text(fm.Intro), cols-2) {
			add(-1, -1, func(f *frame, r int) { f.putLine(r, 1, l) })
		}
		add(-1, -1, func(*frame, int) {})
	}

	for i, fs := range states {
		focused := i == focus
		lbl := fs.f.Label
		if c := fs.f.Constraints(); c != "" && fs.f.Kind != form.Boolean {
			lbl += "  (" + c + ")"
		}
		prefix := "  "
		lst := theme.Style{Bold: true}
		if focused {
			prefix, lst = marker, theme.Style{FG: theme.Accent, Bold: true}
		}

		switch fs.f.Kind {
		case form.SingleLine:
			add(i, -1, func(f *frame, r int) { f.put(r, 1, prefix+lbl, lst, cols-2) })
			text, cur := u.inputWindow(fs, inner-2)
			c := -1
			if focused {
				c = 3 + cur
			}
			add(i, c, func(f *frame, r int) {
				f.put(r, 2, "["+term.Pad(text, inner-2)+"]", theme.Style{FG: theme.InputFG, BG: theme.InputBG}, inner)
			})
		case form.MultiLine:
			add(i, -1, func(f *frame, r int) { f.put(r, 1, prefix+lbl, lst, cols-2) })
			vis, curRow, curCol := u.textareaWindow(fs, inner-2, multiLineRows)
			for j, l := range vis {
				c := -1
				if focused && j == curRow {
					c = 3 + curCol
				}
				add(i, c, func(f *frame, r int) {
					f.put(r, 2, "|"+term.Pad(l, inner-2)+"|", theme.Style{FG: theme.InputFG, BG: theme.InputBG}, inner)
				})
			}
		case form.Choice:
			add(i, -1, func(f *frame, r int) { f.put(r, 1, prefix+lbl, lst, cols-2) })
			for j, o := range fs.f.Options {
				mark := "( )"
				if fs.f.Multi {
					mark = "[ ]"
				}
				if isChosen(fs.value(), o.Value) {
					mark = "(*)"
					if fs.f.Multi {
						mark = "[x]"
					}
				}
				st := theme.Style{}
				if focused && j == fs.opt {
					st = theme.Style{FG: theme.FocusFG, BG: theme.FocusBG}
				}
				text := mark + " " + o.Label
				add(i, -1, func(f *frame, r int) { f.put(r, 4, text, st, cols-6) })
			}
		case form.Boolean:
			mark := "[ ]"
			if fs.value() == form.True {
				mark = "[x]"
			}
			st := lst
			if focused {
				st = theme.Style{FG: theme.FocusFG, BG: theme.FocusBG, Bold: true}
			}
			text := prefix + mark + " " + fs.f.Label
			add(i, -1, func(f *frame, r int) { f.put(r, 1, text, st, cols-2) })
		}
		if fs.f.Help != "" && focused {
			for _, l := range WrapLine(Styled(fs.f.Help, theme.Style{FG: theme.Muted}), cols-6) {
				add(i, -1, func(f *frame, r int) { f.putLine(r, 4, l) })
			}
		}
		if fs.err != nil {
			msg := "Error: " + fs.err.Error()
			add(i, -1, func(f *frame, r int) { f.put(r, 4, msg, theme.Style{FG: theme.Error, Bold: true}, cols-6) })
		}
		add(i, -1, func(*frame, int) {})
	}

	submit := len(states)
	btn := func(label string, on bool) (string, theme.Style) {
		if on {
			return "[ " + label + " ]", theme.Style{FG: theme.FocusFG, BG: theme.FocusBG, Bold: true}
		}
		return "[ " + label + " ]", theme.Style{FG: theme.Accent}
	}
	add(submit, -1, func(f *frame, r int) {
		t1, s1 := btn("Submit", focus == submit)
		t2, s2 := btn("Cancel", focus == submit+1)
		f.put(r, 2, t1, s1, term.Width(t1))
		f.put(r, 4+term.Width(t1), t2, s2, term.Width(t2))
	})

	// Scroll so the focused field's rows are visible.
	body := f.bodyRows()
	target := min(focus, submit)
	first, last := -1, -1
	for i, r := range rows {
		if r.field == target {
			if first < 0 {
				first = i
			}
			last = i
		}
	}
	if first >= 0 {
		if first < scroll {
			scroll = first
		}
		if last >= scroll+body {
			scroll = last - body + 1
		}
	}
	scroll = max(0, min(scroll, len(rows)-body))
	scroll = max(scroll, 0)

	for i := 0; i < body && scroll+i < len(rows); i++ {
		r := rows[scroll+i]
		r.draw(f, f.bodyTop()+i)
		if r.cursor >= 0 {
			f.curRow, f.curCol = f.bodyTop()+i, r.cursor
		}
	}
	_ = f.flush()
	return scroll
}

// inputWindow returns the visible part of a single-line input and the
// cursor's cell offset within it, scrolling horizontally to keep the cursor
// in view. Passwords are masked.
func (u *Screen) inputWindow(fs *fieldState, width int) (string, int) {
	line := fs.ed.lines[0]
	if fs.f.Subtype == form.Password {
		mask := []rune(u.sym("•", "*"))[0]
		masked := make([]rune, len(line))
		for i := range masked {
			masked[i] = mask
		}
		line = masked
	}
	start := 0
	for term.Width(string(line[start:fs.ed.col])) >= width {
		start++
	}
	vis := term.Truncate(term.Sanitize(string(line[start:]), false), width)
	return vis, term.Width(string(line[start:fs.ed.col]))
}

// textareaWindow soft-wraps the editor's lines to width and returns up to
// height visible rows around the cursor, plus the cursor's row and column.
func (u *Screen) textareaWindow(fs *fieldState, width, height int) ([]string, int, int) {
	type vrow struct {
		text      string
		line, off int // logical line and rune offset of the row start
	}
	var vrows []vrow
	curV, curC := 0, 0
	for li, l := range fs.ed.lines {
		off := 0
		for {
			seg := term.Truncate(string(l[off:]), width)
			n := len([]rune(seg))
			if li == fs.ed.row && fs.ed.col >= off && (fs.ed.col < off+n || off+n == len(l)) {
				if fs.ed.col-off < n || off+n == len(l) {
					curV, curC = len(vrows), term.Width(string(l[off:fs.ed.col]))
				}
			}
			vrows = append(vrows, vrow{term.Sanitize(seg, false), li, off})
			off += n
			if off >= len(l) || n == 0 {
				break
			}
		}
	}
	if curC >= width { // cursor at end of a full row: show it on the next row
		curC = width - 1
	}
	top := max(0, min(curV-height+1, len(vrows)-height))
	top = max(top, 0)
	var out []string
	for i := top; i < len(vrows) && i < top+height; i++ {
		out = append(out, vrows[i].text)
	}
	for len(out) < height {
		out = append(out, "")
	}
	return out, curV - top, curC
}
