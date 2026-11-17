package wall

import (
	"html"
	"strings"
	"unicode"

	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// Wall lines support only emphasis, in markdown syntax: **bold**, *italic*
// and _italic_ (combinable, e.g. ***both***). A backslash shows a marker
// as itself (\*). Markers without a partner are shown as typed. Nothing
// else is interpreted: links, headings and code stay plain text.

// segment is a run of text with one style.
type segment struct {
	Text         string
	Bold, Italic bool
}

// token is literal text or an emphasis marker ("*", "**", "***" or "_").
type token struct {
	text   string
	marker string
	paired bool
}

func isWordRune(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

// tokenize splits s into text and markers. "_" only counts as a marker at
// a word boundary, so snake_case words stay as typed.
func tokenize(s string) []token {
	rs := []rune(s)
	var out []token
	var text strings.Builder
	flush := func() {
		if text.Len() > 0 {
			out = append(out, token{text: text.String()})
			text.Reset()
		}
	}
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		switch {
		case r == '\\' && i+1 < len(rs) && strings.ContainsRune(`\*_`, rs[i+1]):
			text.WriteRune(rs[i+1])
			i++
		case r == '*':
			flush()
			n := 1
			for i+n < len(rs) && rs[i+n] == '*' {
				n++
			}
			i += n - 1
			for ; n > 3; n -= 2 {
				out = append(out, token{marker: "**"})
			}
			out = append(out, token{marker: strings.Repeat("*", n)})
		case r == '_' && (i == 0 || !isWordRune(rs[i-1]) || i+1 == len(rs) || !isWordRune(rs[i+1])):
			flush()
			out = append(out, token{marker: "_"})
		default:
			text.WriteRune(r)
		}
	}
	flush()
	return out
}

// pair matches each marker with the nearest open marker of the same kind;
// markers left open in between are shown as typed. A "***" run is split
// into "**" and "*", ordered to close the innermost open one first, so
// ***both*** nests.
func pair(in []token) []token {
	var toks []token
	var open []int
	one := func(t token) {
		toks = append(toks, t)
		i := len(toks) - 1
		for j := len(open) - 1; j >= 0; j-- {
			if toks[open[j]].marker == t.marker {
				toks[open[j]].paired, toks[i].paired = true, true
				open = open[:j]
				return
			}
		}
		open = append(open, i)
	}
	for _, t := range in {
		switch {
		case t.marker == "":
			toks = append(toks, t)
		case t.marker == "***":
			if len(open) > 0 && toks[open[len(open)-1]].marker == "*" {
				one(token{marker: "*"})
				one(token{marker: "**"})
			} else {
				one(token{marker: "**"})
				one(token{marker: "*"})
			}
		default:
			one(t)
		}
	}
	return toks
}

// parse turns a wall line into styled segments.
func parse(s string) []segment {
	toks := pair(tokenize(s))

	var out []segment
	var bold, italic bool
	add := func(text string) {
		if text == "" {
			return
		}
		if n := len(out); n > 0 && out[n-1].Bold == bold && out[n-1].Italic == italic {
			out[n-1].Text += text
			return
		}
		out = append(out, segment{Text: text, Bold: bold, Italic: italic})
	}
	for _, t := range toks {
		switch {
		case t.marker == "":
			add(t.text)
		case !t.paired:
			add(t.marker)
		case t.marker == "**":
			bold = !bold
		default:
			italic = !italic
		}
	}
	return out
}

// Plain is a wall line without its markers (for exports and screen
// readers' plain output).
func Plain(s string) string {
	var b strings.Builder
	for _, seg := range parse(s) {
		b.WriteString(seg.Text)
	}
	return b.String()
}

// HTML renders a wall line with <strong> and <em>, escaping all text.
func HTML(s string) string {
	var b strings.Builder
	for _, seg := range parse(s) {
		t := html.EscapeString(seg.Text)
		if seg.Italic {
			t = "<em>" + t + "</em>"
		}
		if seg.Bold {
			t = "<strong>" + t + "</strong>"
		}
		b.WriteString(t)
	}
	return b.String()
}

// Spans renders a wall line as styled TUI spans.
func Spans(s string) tui.Line {
	var l tui.Line
	for _, seg := range parse(s) {
		l = append(l, tui.Span{Text: seg.Text, Style: theme.Style{Bold: seg.Bold, Italic: seg.Italic}})
	}
	return l
}
