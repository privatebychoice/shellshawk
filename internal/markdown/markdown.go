// Package markdown parses user markdown once and renders it for the web
// (HTML) and the TUI (styled lines for full-screen, plain marked-up lines for
// screen-reader mode), following docs/DESIGN.md §8.
//
// Supported: paragraphs, bold, italic, strikethrough, inline code, headings
// (three levels; 4-6 are shown as 3), block quotes, ordered and unordered lists,
// horizontal rules, code blocks, links and bare URLs. Images are never
// loaded; raw HTML is shown as text and never executed. Every link carries
// a pbc-classification privacy grade.
package markdown

import (
	"net/url"
	"strings"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/text"

	"go.privatebychoice.com/shellshawk/internal/linkgrade"
)

// MaxSource bounds the markdown accepted for rendering.
const MaxSource = 256 * 1024

// Grader grades links. *linkgrade.Grader implements it.
type Grader interface {
	Grade(rawURL string) linkgrade.Result
}

// newMarkdown returns the shared goldmark configuration: CommonMark plus
// strikethrough and bare-URL linking (http/https only, plus email).
func newMarkdown(extra ...goldmark.Option) goldmark.Markdown {
	opts := append([]goldmark.Option{
		goldmark.WithExtensions(
			extension.Strikethrough,
			extension.NewLinkify(extension.WithLinkifyAllowedProtocols([]string{"http:", "https:"})),
		),
	}, extra...)
	return goldmark.New(opts...)
}

// parse returns the document AST for src.
func parse(src []byte) ast.Node {
	if len(src) > MaxSource {
		src = src[:MaxSource]
	}
	return newMarkdown().Parser().Parse(text.NewReader(src))
}

// safeURL returns the link destination if it is http, https or mailto, and
// false otherwise (javascript:, data:, file:, relative paths, …). "www."
// links from bare-URL detection get https://.
func safeURL(dest string) (string, bool) {
	dest = strings.TrimSpace(dest)
	if strings.HasPrefix(strings.ToLower(dest), "www.") {
		dest = "https://" + dest
	}
	u, err := url.Parse(dest)
	if err != nil {
		return "", false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		if u.Host == "" {
			return "", false
		}
		return u.String(), true
	case "mailto":
		if u.Opaque == "" {
			return "", false
		}
		return u.String(), true
	}
	return "", false
}

// linkTarget extracts the destination of a Link or AutoLink.
func linkTarget(n ast.Node, src []byte) (string, bool) {
	switch v := n.(type) {
	case *ast.Link:
		return string(v.Destination), true
	case *ast.AutoLink:
		u := string(v.URL(src))
		if label := string(v.Label(src)); strings.HasPrefix(strings.ToLower(label), "www.") {
			u = label // goldmark adds http://; safeURL adds https:// instead
		}
		if v.AutoLinkType == ast.AutoLinkEmail && !strings.HasPrefix(strings.ToLower(u), "mailto:") {
			u = "mailto:" + u
		}
		return u, true
	}
	return "", false
}

// plainText returns the text content of inline children.
func plainText(n ast.Node, src []byte) string {
	var b strings.Builder
	_ = ast.Walk(n, func(c ast.Node, entering bool) (ast.WalkStatus, error) {
		if !entering {
			return ast.WalkContinue, nil
		}
		switch v := c.(type) {
		case *ast.Text:
			b.Write(v.Segment.Value(src))
			if v.SoftLineBreak() || v.HardLineBreak() {
				b.WriteByte(' ')
			}
		case *ast.String:
			b.Write(v.Value)
		case *ast.CodeSpan:
			b.WriteString(codeSpanText(v, src))
			return ast.WalkSkipChildren, nil
		case *ast.AutoLink:
			b.Write(v.Label(src))
		}
		return ast.WalkContinue, nil
	})
	return b.String()
}

func codeSpanText(n *ast.CodeSpan, src []byte) string {
	var b strings.Builder
	for c := n.FirstChild(); c != nil; c = c.NextSibling() {
		if t, ok := c.(*ast.Text); ok {
			b.Write(t.Segment.Value(src))
		}
	}
	return b.String()
}

// UnderTitle is the heading level for "#" in content shown directly under
// a page's own title (level 1), so a member's headings never compete with
// it.
const UnderTitle = 2

// headingLevel is the level a heading is shown at. The author's level is
// limited to 1-3 and then moved down so that "#" is shown at top, keeping
// the page outline intact; top below 1 means 1 (levels as written). The
// result is at most 6.
func headingLevel(n *ast.Heading, top int) int {
	return min(min(max(n.Level, 1), 3)+max(top, 1)-1, 6)
}
