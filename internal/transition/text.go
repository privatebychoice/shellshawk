package transition

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// cp437 maps bytes 0x80–0xFF of code page 437, the character set of
// classic BBS art, to Unicode.
var cp437 = []rune("" +
	"ÇüéâäàåçêëèïîìÄÅ" + "ÉæÆôöòûùÿÖÜ¢£¥₧ƒ" +
	"áíóúñÑªº¿⌐¬½¼¡«»" + "░▒▓│┤╡╢╖╕╣║╗╝╜╛┐" +
	"└┴┬├─┼╞╟╚╔╩╦╠═╬╧" + "╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀" +
	"αßΓπΣσµτΦΘΩδ∞φε∩" + "≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ")

// ansiSeq matches ANSI escape sequences (CSI and two-character escapes).
var ansiSeq = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[@-Z\\-_]`)

const tabWidth = 8

// Clean turns an uploaded or edited file into the text that is stored and
// shown:
//
//   - a SAUCE record (from the first Ctrl-Z) is dropped;
//   - text that is not valid UTF-8 is read as code page 437;
//   - ANSI escape sequences are removed, keeping only the text;
//   - tabs are expanded, other control characters removed, line endings
//     made "\n", and trailing spaces and blank lines trimmed.
//
// It fails if the file is too big or has no visible text.
func Clean(data []byte) (string, error) {
	if len(data) > MaxFileBytes {
		return "", fmt.Errorf("%w: files can be at most %d KiB", ErrInvalid, MaxFileBytes>>10)
	}
	if i := bytes.IndexByte(data, 0x1a); i >= 0 {
		data = data[:i]
	}
	var s string
	if utf8.Valid(data) {
		s = string(data)
	} else {
		var b strings.Builder
		for _, c := range data {
			if c < 0x80 {
				b.WriteByte(c)
			} else {
				b.WriteRune(cp437[c-0x80])
			}
		}
		s = b.String()
	}
	s = ansiSeq.ReplaceAllString(s, "")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(term.Sanitize(expandTabs(l), false), "  ")
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	for len(lines) > 0 && lines[0] == "" {
		lines = lines[1:]
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("%w: the file has no text", ErrInvalid)
	}
	return strings.Join(lines, "\n"), nil
}

func expandTabs(l string) string {
	if !strings.Contains(l, "\t") {
		return l
	}
	var b strings.Builder
	col := 0
	for _, r := range l {
		if r == '\t' {
			n := tabWidth - col%tabWidth
			b.WriteString(strings.Repeat(" ", n))
			col += n
			continue
		}
		b.WriteRune(r)
		col += term.RuneWidth(r)
	}
	return b.String()
}

// ASCII approximates text for terminals that can only show ASCII: line
// and box drawing become - | +, shading and blocks become #, and any other
// character outside ASCII becomes ?.
func ASCII(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x80:
			return r
		case r == 0xa0:
			return ' '
		case r == '·' || r == '∙':
			return '.'
		case strings.ContainsRune("─━═╌╍┄┅┈┉", r):
			return '-'
		case strings.ContainsRune("│┃║╎╏┆┇┊┋", r):
			return '|'
		case r >= 0x2500 && r <= 0x257f: // other box drawing: corners, joins
			return '+'
		case r >= 0x2580 && r <= 0x259f, r == '■': // blocks and shades
			return '#'
		}
		return '?'
	}, s)
}

// Reason returns the message of an error from this package for the person
// who made the request, without the package prefix: "Use 1 to 40
// lowercase letters, …".
func Reason(err error) string {
	msg := err.Error()
	for _, e := range []error{ErrInvalid, ErrTooMany} {
		msg = strings.TrimPrefix(msg, e.Error()+": ")
	}
	msg = strings.TrimPrefix(msg, "transition: ")
	if msg == "" {
		return ""
	}
	r, n := utf8.DecodeRuneInString(msg)
	msg = string(unicode.ToUpper(r)) + msg[n:]
	if !strings.HasSuffix(msg, ".") {
		msg += "."
	}
	return msg
}
