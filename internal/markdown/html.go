package markdown

import (
	"bytes"
	"fmt"
	"html"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/renderer"
	"github.com/yuin/goldmark/util"
)

// RenderHTML renders markdown as sanitised HTML for the web interface. Raw
// HTML in the source is shown as escaped text, images are replaced by their
// description, only http/https/mailto links are kept, and every link gets a
// rel="nofollow noopener noreferrer ugc" attribute and a privacy grade badge.
func RenderHTML(src string, g Grader) (string, error) {
	b := []byte(src)
	if len(b) > MaxSource {
		b = b[:MaxSource]
	}
	md := newMarkdown(goldmark.WithRendererOptions(
		// Priority 100 runs ahead of goldmark's defaults (1000).
		renderer.WithNodeRenderers(util.Prioritized(&htmlRenderer{g: g}, 100)),
	))
	var out bytes.Buffer
	if err := md.Convert(b, &out); err != nil {
		return "", fmt.Errorf("markdown: %w", err)
	}
	return out.String(), nil
}

type htmlRenderer struct{ g Grader }

func (r *htmlRenderer) RegisterFuncs(reg renderer.NodeRendererFuncRegisterer) {
	reg.Register(ast.KindLink, r.link)
	reg.Register(ast.KindAutoLink, r.link)
	reg.Register(ast.KindImage, r.image)
	reg.Register(ast.KindHeading, r.heading)
	reg.Register(ast.KindRawHTML, r.rawHTML)
	reg.Register(ast.KindHTMLBlock, r.htmlBlock)
}

const linkRel = "nofollow noopener noreferrer ugc"

func (r *htmlRenderer) badge(u string) string {
	letter, name := "?", "Unclassified"
	if r.g != nil {
		res := r.g.Grade(u)
		letter, name = res.Letter, res.Name
	}
	class := "pbc-grade-unknown"
	if letter != "?" {
		class = "pbc-grade-" + strings.ToLower(letter)
	}
	// The badge is text, so the grade never depends on colour alone.
	return fmt.Sprintf(` <span class="pbc-grade %s" title="Privacy grade %s: %s">%s %s</span>`,
		class, html.EscapeString(letter), html.EscapeString(name), html.EscapeString(letter), html.EscapeString(name))
}

func (r *htmlRenderer) link(w util.BufWriter, src []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	dest, _ := linkTarget(n, src)
	u, ok := safeURL(dest)
	auto, isAuto := n.(*ast.AutoLink)
	if !entering {
		if ok && !isAuto {
			_, _ = w.WriteString("</a>" + r.badge(u))
		}
		return ast.WalkContinue, nil
	}
	if !ok {
		_, _ = w.WriteString(html.EscapeString(plainText(n, src)))
		_, _ = w.WriteString(` <span class="md-link-removed">(link removed: unsupported address)</span>`)
		return ast.WalkSkipChildren, nil
	}
	_, _ = fmt.Fprintf(w, `<a href="%s" rel="%s">`, html.EscapeString(u), linkRel)
	if isAuto {
		_, _ = w.WriteString(html.EscapeString(string(auto.Label(src))) + "</a>" + r.badge(u))
		return ast.WalkSkipChildren, nil
	}
	return ast.WalkContinue, nil
}

func (r *htmlRenderer) image(w util.BufWriter, src []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		_, _ = w.WriteString(`<span class="md-image-omitted">Image not shown: ` + html.EscapeString(plainText(n, src)) + `</span>`)
	}
	return ast.WalkSkipChildren, nil
}

func (r *htmlRenderer) heading(w util.BufWriter, _ []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	lvl := headingLevel(n.(*ast.Heading))
	if entering {
		_, _ = fmt.Fprintf(w, "<h%d>", lvl)
	} else {
		_, _ = fmt.Fprintf(w, "</h%d>\n", lvl)
	}
	return ast.WalkContinue, nil
}

func (r *htmlRenderer) rawHTML(w util.BufWriter, src []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if entering {
		segs := n.(*ast.RawHTML).Segments
		for i := 0; i < segs.Len(); i++ {
			seg := segs.At(i)
			_, _ = w.WriteString(html.EscapeString(string(seg.Value(src))))
		}
	}
	return ast.WalkSkipChildren, nil
}

func (r *htmlRenderer) htmlBlock(w util.BufWriter, src []byte, n ast.Node, entering bool) (ast.WalkStatus, error) {
	if !entering {
		return ast.WalkContinue, nil
	}
	b := n.(*ast.HTMLBlock)
	var s strings.Builder
	for i := 0; i < b.Lines().Len(); i++ {
		seg := b.Lines().At(i)
		s.Write(seg.Value(src))
	}
	if b.HasClosure() {
		s.Write(b.ClosureLine.Value(src))
	}
	_, _ = w.WriteString(`<pre class="md-html-source">` + html.EscapeString(strings.TrimRight(s.String(), "\n")) + "</pre>\n")
	return ast.WalkSkipChildren, nil
}
