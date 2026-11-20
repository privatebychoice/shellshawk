package term

import (
	"strings"
	"unicode"
)

// Sanitize removes everything from user-supplied text that a terminal could
// interpret: C0/C1 control characters (including ESC, so no ANSI/OSC
// injection), DEL, and bidirectional overrides that can disguise text. It
// also removes invisible characters that can make two different names or
// lines look the same (zero-width space, word joiner, U+FEFF, U+180E);
// the zero-width joiner and non-joiner stay, as emoji and several scripts
// need them. Tabs become a space. If keepNewlines is set, '\n' is kept.
func Sanitize(s string, keepNewlines bool) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' && keepNewlines:
			return r
		case r == '\t':
			return ' '
		case unicode.IsControl(r), isBidi(r), isInvisible(r):
			return -1
		}
		return r
	}, s)
}

func isBidi(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F || r == 0x061C
}

// isInvisible reports characters with no visible form that are not needed
// to write any language.
func isInvisible(r rune) bool {
	return r == 0x200B || r == 0x2060 || r == 0xFEFF || r == 0x180E
}

// RuneWidth is the number of terminal cells r occupies: 0 for combining and
// zero-width characters, 2 for East Asian wide characters and most emoji,
// otherwise 1. It is an approximation without a full Unicode width table.
func RuneWidth(r rune) int {
	switch {
	case r == 0, unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r), unicode.Is(unicode.Cf, r), unicode.IsControl(r):
		return 0
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0x303E, // CJK radicals, punctuation
		r >= 0x3041 && r <= 0x33FF, // kana, CJK symbols
		r >= 0x3400 && r <= 0x4DBF, // CJK ext A
		r >= 0x4E00 && r <= 0x9FFF, // CJK unified
		r >= 0xA000 && r <= 0xA4CF, // Yi
		r >= 0xAC00 && r <= 0xD7A3, // Hangul syllables
		r >= 0xF900 && r <= 0xFAFF, // CJK compatibility
		r >= 0xFE30 && r <= 0xFE4F, // CJK compatibility forms
		r >= 0xFF00 && r <= 0xFF60, // fullwidth forms
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x1F300 && r <= 0x1F64F, // emoji
		r >= 0x1F900 && r <= 0x1F9FF,
		r >= 0x20000 && r <= 0x3FFFD: // CJK ext B+
		return 2
	}
	return 1
}

// Width is the number of terminal cells s occupies.
func Width(s string) int {
	w := 0
	for _, r := range s {
		w += RuneWidth(r)
	}
	return w
}

// Truncate cuts s to at most w cells.
func Truncate(s string, w int) string {
	used := 0
	for i, r := range s {
		rw := RuneWidth(r)
		if used+rw > w {
			return s[:i]
		}
		used += rw
	}
	return s
}

// Pad right-pads s with spaces to w cells (truncating if longer).
func Pad(s string, w int) string {
	s = Truncate(s, w)
	return s + strings.Repeat(" ", max(0, w-Width(s)))
}

// Wrap breaks s into lines of at most w cells, preferring spaces. Existing
// newlines are kept. Words longer than w are split.
func Wrap(s string, w int) []string {
	if w < 1 {
		w = 1
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		line, lineW := "", 0
		for _, word := range strings.Split(para, " ") {
			ww := Width(word)
			switch {
			case lineW == 0:
			case lineW+1+ww <= w:
				line += " "
				lineW++
			default:
				out = append(out, line)
				line, lineW = "", 0
			}
			for ww > w-lineW && lineW == 0 && ww > w {
				head := Truncate(word, w)
				out = append(out, head)
				word = word[len(head):]
				ww = Width(word)
			}
			line += word
			lineW += ww
		}
		out = append(out, line)
	}
	return out
}

// Screen control sequences.
const (
	AltScreenOn     = "\x1b[?1049h"
	AltScreenOff    = "\x1b[?1049l"
	CursorHide      = "\x1b[?25l"
	CursorShow      = "\x1b[?25h"
	ClearScreen     = "\x1b[2J"
	ClearLine       = "\x1b[2K"
	BracketPasteOn  = "\x1b[?2004h"
	BracketPasteOff = "\x1b[?2004l"
)

// MoveTo positions the cursor at 0-based row and column.
func MoveTo(row, col int) string {
	return "\x1b[" + itoa(row+1) + ";" + itoa(col+1) + "H"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
