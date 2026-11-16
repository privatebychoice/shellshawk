package markdown

import (
	"fmt"
	"strings"

	"github.com/yuin/goldmark/ast"
	extast "github.com/yuin/goldmark/extension/ast"

	"go.privatebychoice.com/shellshawk/internal/linkgrade"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// TUIOptions controls terminal rendering.
type TUIOptions struct {
	// Width is the full-screen width in cells; output is wrapped to it.
	// Ignored in accessible mode (the client's terminal wraps).
	Width int
	// Accessible renders for screen readers: no colour, no decoration;
	// structure is announced in words (docs/DESIGN.md §8).
	Accessible bool
	// Unicode allows box-drawing characters (horizontal rules).
	Unicode bool
	// Grader grades links; nil shows every link as unclassified.
	Grader Grader
}

// RenderTUI renders markdown source as display lines.
func RenderTUI(src string, o TUIOptions) []tui.Line {
	b := []byte(src)
	r := &tuiRenderer{src: b, o: o}
	r.blocks(parse(b), &prefix{}, theme.Style{}, 0, 0, true)
	// Trim trailing blank lines.
	for len(r.out) > 0 && strings.TrimSpace(r.out[len(r.out)-1].Plain()) == "" {
		r.out = r.out[:len(r.out)-1]
	}
	return r.out
}

// Page renders markdown as a tui.Page.
func Page(title, src string, o TUIOptions) tui.Page {
	return tui.Page{Title: title, Lines: RenderTUI(src, o)}
}

type tuiRenderer struct {
	src []byte
	o   TUIOptions
	out []tui.Line
}

// prefix is what each output line in a container starts with: list
// bullets and quote markers. The first line of a list item differs from its
// continuation lines.
type prefix struct {
	first, rest tui.Line
	used        bool
}

func (p *prefix) next() tui.Line {
	if !p.used {
		p.used = true
		return p.first
	}
	return p.rest
}

func concat(a, b tui.Line) tui.Line {
	out := make(tui.Line, 0, len(a)+len(b))
	return append(append(out, a...), b...)
}

func lineWidth(l tui.Line) int { return term.Width(l.Plain()) }

func (r *tuiRenderer) emit(p *prefix, l tui.Line) { r.out = append(r.out, concat(p.next(), l)) }

func (r *tuiRenderer) blank(p *prefix) {
	if r.o.Accessible {
		r.out = append(r.out, tui.Text(""))
		return
	}
	r.out = append(r.out, p.rest)
}

// avail is the width left after the prefix.
func (r *tuiRenderer) avail(p *prefix) int {
	return max(10, r.o.Width-max(lineWidth(p.first), lineWidth(p.rest)))
}

func (r *tuiRenderer) wrap() bool { return !r.o.Accessible && r.o.Width > 0 }

// blocks renders n's block children separated by blank lines (unless tight).
func (r *tuiRenderer) blocks(n ast.Node, p *prefix, base theme.Style, quote, list int, loose bool) {
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		if c != n.FirstChild() && loose {
			r.blank(p)
		}
		r.block(c, p, base, quote, list)
	}
}

func (r *tuiRenderer) block(n ast.Node, p *prefix, base theme.Style, quote, list int) {
	acc := r.o.Accessible
	switch v := n.(type) {
	case *ast.Paragraph, *ast.TextBlock:
		r.paragraph(v, p, base)

	case *ast.Heading:
		lvl := headingLevel(v)
		txt := strings.TrimSpace(plainText(v, r.src))
		if acc {
			r.emit(p, tui.Text(fmt.Sprintf("Heading level %d: %s", lvl, txt)))
			return
		}
		marker := [3]string{"#   ", "##  ", "### "}[lvl-1]
		st := theme.Style{FG: theme.HeadingFG, BG: theme.HeadingBG, Bold: true}
		w := r.avail(p)
		for _, l := range term.Wrap(marker+txt, w) {
			r.emit(p, tui.Styled(term.Pad(l, w), st))
		}

	case *ast.ThematicBreak:
		if acc {
			r.emit(p, tui.Text("Section break."))
			return
		}
		ch := "-"
		if r.o.Unicode {
			ch = "─"
		}
		r.emit(p, tui.Styled(strings.Repeat(ch, r.avail(p)), theme.Style{FG: theme.Rule}))

	case *ast.CodeBlock, *ast.FencedCodeBlock:
		r.codeBlock(v, p)

	case *ast.Blockquote:
		if acc {
			label := "Quote:"
			if quote > 0 {
				label = fmt.Sprintf("Quote level %d:", quote+1)
			}
			r.emit(p, tui.Text(label))
			r.blocks(v, p, base, quote+1, list, true)
			r.emit(p, tui.Text("End quote."))
			return
		}
		m := tui.Line{{Text: "> ", Style: theme.Style{FG: theme.QuoteMarker, Bold: true}}}
		child := &prefix{first: concat(p.next(), m), rest: concat(p.rest, m)}
		r.blocks(v, child, theme.Style{FG: theme.QuoteText}, quote+1, list, true)

	case *ast.List:
		r.list(v, p, base, quote, list)

	case *ast.HTMLBlock:
		// Raw HTML is shown as text, never interpreted.
		var b strings.Builder
		for i := 0; i < v.Lines().Len(); i++ {
			seg := v.Lines().At(i)
			b.Write(seg.Value(r.src))
		}
		if v.HasClosure() {
			b.Write(v.ClosureLine.Value(r.src))
		}
		for _, l := range strings.Split(strings.TrimRight(b.String(), "\n"), "\n") {
			r.emit(p, tui.Styled(l, base))
		}

	default:
		if n.FirstChild() != nil {
			r.blocks(n, p, base, quote, list, true)
		}
	}
}

func (r *tuiRenderer) list(v *ast.List, p *prefix, base theme.Style, quote, depth int) {
	acc := r.o.Accessible
	n := v.ChildCount()
	if acc {
		noun := "items"
		if n == 1 {
			noun = "item"
		}
		kind := "List"
		if depth > 0 {
			kind = "Sub-list"
		}
		r.emit(p, tui.Text(fmt.Sprintf("%s, %d %s:", kind, n, noun)))
	}
	i := 0
	for item := v.FirstChild(); item != nil; item = item.NextSibling() {
		if i > 0 && !v.IsTight {
			r.blank(p)
		}
		var first, rest tui.Line
		if v.IsOrdered() {
			num := fmt.Sprintf("%d", v.Start+i)
			if acc {
				first = tui.Text(num + ". ")
			} else {
				first = tui.Line{
					{Text: num, Style: theme.Style{FG: theme.ListNumber, Bold: true}},
					{Text: ".", Style: theme.Style{FG: theme.ListDot}},
					{Text: " "},
				}
			}
		} else {
			if acc {
				first = tui.Text("- ")
			} else {
				first = tui.Line{{Text: "-", Style: theme.Style{FG: theme.ListBullet, Bold: true}}, {Text: " "}}
			}
		}
		if !acc {
			rest = tui.Text(strings.Repeat(" ", lineWidth(first)))
		}
		var child *prefix
		if acc {
			// Screen readers get the marker on the item's first line only;
			// nesting is announced ("Sub-list") rather than indented.
			child = &prefix{first: concat(p.next(), first), rest: p.rest}
		} else {
			child = &prefix{first: concat(p.next(), first), rest: concat(p.rest, rest)}
		}
		r.blocks(item, child, base, quote, depth+1, !v.IsTight)
		i++
	}
	if acc {
		r.emit(p, tui.Text("End of list."))
	}
}

func (r *tuiRenderer) codeBlock(n ast.Node, p *prefix) {
	var lines []string
	for i := 0; i < n.Lines().Len(); i++ {
		seg := n.Lines().At(i)
		lines = append(lines, strings.TrimRight(string(seg.Value(r.src)), "\n"))
	}
	lang := ""
	if f, ok := n.(*ast.FencedCodeBlock); ok {
		lang = string(f.Language(r.src))
	}
	if r.o.Accessible {
		head := "Code block start"
		if lang != "" {
			head += ", language " + lang
		}
		noun := "lines"
		if len(lines) == 1 {
			noun = "line"
		}
		r.emit(p, tui.Text(fmt.Sprintf("%s, %d %s:", head, len(lines), noun)))
		for _, l := range lines {
			r.emit(p, tui.Text(strings.ReplaceAll(l, "\t", "    ")))
		}
		r.emit(p, tui.Text("Code block end."))
		return
	}
	st := theme.Style{FG: theme.CodeFG, BG: theme.CodeBG}
	w := r.avail(p)
	for _, l := range lines {
		l = "  " + strings.ReplaceAll(l, "\t", "    ")
		// Code is hard-wrapped, never word-wrapped, so columns line up.
		for {
			chunk := term.Truncate(l, w)
			r.emit(p, tui.Styled(term.Pad(chunk, w), st))
			l = l[len(chunk):]
			if l == "" || chunk == "" {
				break
			}
			l = "  " + l
		}
	}
}

// paragraph renders inline content, wrapping in full-screen mode.
func (r *tuiRenderer) paragraph(n ast.Node, p *prefix, base theme.Style) {
	lines := []tui.Line{nil}
	add := func(s tui.Span) { lines[len(lines)-1] = append(lines[len(lines)-1], s) }
	brk := func() { lines = append(lines, nil) }
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		r.inline(c, base, add, brk)
	}
	for _, l := range lines {
		if !r.wrap() {
			r.emit(p, l)
			continue
		}
		for _, wl := range tui.WrapLine(l, r.avail(p)) {
			r.emit(p, wl)
		}
	}
}

func (r *tuiRenderer) inline(n ast.Node, st theme.Style, add func(tui.Span), brk func()) {
	acc := r.o.Accessible
	switch v := n.(type) {
	case *ast.Text:
		add(tui.Span{Text: string(v.Segment.Value(r.src)), Style: st})
		switch {
		case v.HardLineBreak():
			brk()
		case v.SoftLineBreak():
			add(tui.Span{Text: " ", Style: st})
		}
	case *ast.String:
		add(tui.Span{Text: string(v.Value), Style: st})
	case *ast.Emphasis:
		inner := st
		if v.Level >= 2 {
			inner.Bold = true
		} else {
			inner.Italic = true
		}
		for c := v.FirstChild(); c != nil; c = c.NextSibling() {
			r.inline(c, inner, add, brk)
		}
	case *ast.CodeSpan:
		txt := codeSpanText(v, r.src)
		if acc {
			add(tui.Span{Text: "`" + txt + "`"})
		} else {
			add(tui.Span{Text: txt, Style: theme.Style{FG: theme.CodeFG, BG: theme.CodeBG}})
		}
	case *ast.Link, *ast.AutoLink:
		r.link(v, st, add)
	case *ast.Image:
		alt := plainText(v, r.src)
		if acc {
			add(tui.Span{Text: "Image not shown: " + alt})
		} else {
			add(tui.Span{Text: "[image not shown: " + alt + "]", Style: theme.Style{FG: theme.Muted}})
		}
	case *ast.RawHTML:
		for i := 0; i < v.Segments.Len(); i++ {
			seg := v.Segments.At(i)
			add(tui.Span{Text: string(seg.Value(r.src)), Style: st})
		}
	case *extast.Strikethrough:
		txt := plainText(v, r.src)
		if acc {
			add(tui.Span{Text: "struck out: " + txt})
		} else {
			add(tui.Span{Text: "~~" + txt + "~~", Style: theme.Style{FG: theme.Muted}})
		}
	default:
		for c := n.FirstChild(); c != nil; c = c.NextSibling() {
			r.inline(c, st, add, brk)
		}
	}
}

// link renders "Link B Considerate: text -> url" (screen-reader mode:
// "Link, grade B Considerate: text, url") in the grade's colour.
func (r *tuiRenderer) link(n ast.Node, st theme.Style, add func(tui.Span)) {
	dest, _ := linkTarget(n, r.src)
	label := strings.TrimSpace(plainText(n, r.src))
	u, ok := safeURL(dest)
	if !ok {
		add(tui.Span{Text: label, Style: st})
		add(tui.Span{Text: " (link removed: unsupported address)", Style: theme.Style{FG: theme.Muted}})
		return
	}
	g := linkgrade.Result{Letter: "?", Name: "Unclassified", Token: theme.GradeUnknown}
	if r.o.Grader != nil {
		g = r.o.Grader.Grade(u)
	}
	same := label == "" || label == u || label == dest || "mailto:"+label == u || "https://"+label == u
	var s string
	if r.o.Accessible {
		s = fmt.Sprintf("Link, grade %s %s: ", g.Letter, g.Name)
		if !same {
			s += label + ", "
		}
		s += u
	} else {
		s = fmt.Sprintf("Link %s %s: ", g.Letter, g.Name)
		if !same {
			s += label + " -> "
		}
		s += u
	}
	add(tui.Span{Text: s, Style: theme.Style{FG: g.Token}})
}
