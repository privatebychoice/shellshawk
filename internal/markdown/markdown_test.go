package markdown

import (
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/linkgrade"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// fakeGrader grades example.org B and everything else unclassified.
type fakeGrader struct{}

func (fakeGrader) Grade(u string) linkgrade.Result {
	if strings.Contains(u, "example.org") {
		return linkgrade.Result{Letter: "B", Name: "Considerate", Token: theme.GradeB}
	}
	return linkgrade.Result{Letter: "?", Name: "Unclassified", Token: theme.GradeUnknown}
}

func plain(lines []tui.Line) []string {
	var out []string
	for _, l := range lines {
		out = append(out, strings.TrimRight(l.Plain(), " "))
	}
	return out
}

func accessible(src string) []string {
	return plain(RenderTUI(src, TUIOptions{Accessible: true, Grader: fakeGrader{}}))
}

func screen(src string, width int) []tui.Line {
	return RenderTUI(src, TUIOptions{Width: width, Unicode: true, Grader: fakeGrader{}})
}

func TestAccessibleRendering(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"emphasis is plain", "Some **bold** and *italic* text.", []string{"Some bold and italic text."}},
		{"headings announced, 4+ clamp to 3", "# One\n\n#### Four", []string{"Heading level 1: One", "", "Heading level 3: Four"}},
		{"rule", "a\n\n---\n\nb", []string{"a", "", "Section break.", "", "b"}},
		{"quote", "> quoted\n> > deeper", []string{"Quote:", "quoted", "", "Quote level 2:", "deeper", "End quote.", "End quote."}},
		{"ordered list", "3. three\n4. four", []string{"List, 2 items:", "3. three", "4. four", "End of list."}},
		{"nested list", "- a\n  - b", []string{"List, 1 item:", "- a", "Sub-list, 1 item:", "- b", "End of list.", "End of list."}},
		{"fenced code", "```go\nx := 1\n\ty\n```", []string{"Code block start, language go, 2 lines:", "x := 1", "    y", "Code block end."}},
		{"inline code keeps backticks", "use `ls -l` here", []string{"use `ls -l` here"}},
		{"graded link with text", "[docs](https://example.org/d)", []string{"Link, grade B Considerate: docs, https://example.org/d"}},
		{"bare url autolinked", "see https://example.org/x now", []string{"see Link, grade B Considerate: https://example.org/x now"}},
		{"www autolink gets https", "www.example.org", []string{"Link, grade B Considerate: https://www.example.org"}},
		{"unclassified link", "[x](https://elsewhere.test/)", []string{"Link, grade ? Unclassified: x, https://elsewhere.test/"}},
		{"javascript link removed", "[click](javascript:alert(1))", []string{"click (link removed: unsupported address)"}},
		{"relative link removed", "[x](/etc/passwd)", []string{"x (link removed: unsupported address)"}},
		{"image never loaded", "![a cat](https://example.org/cat.png)", []string{"Image not shown: a cat"}},
		{"strikethrough", "~~old~~ new", []string{"struck out: old new"}},
		{"raw html shown as text", "hi <script>alert(1)</script>", []string{"hi <script>alert(1)</script>"}},
		{"hard break", "one  \ntwo", []string{"one", "two"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := accessible(tt.src)
			if strings.Join(got, "\n") != strings.Join(tt.want, "\n") {
				t.Errorf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tt.want, "\n"))
			}
		})
	}
}

func TestScreenRendering(t *testing.T) {
	t.Run("heading bar is full width with level marker", func(t *testing.T) {
		got := screen("## Rules", 20)
		if len(got) != 1 || got[0].Plain() != "##  Rules           " {
			t.Fatalf("got %q", plain(got))
		}
		if st := got[0][0].Style; st.BG != theme.HeadingBG || !st.Bold {
			t.Errorf("heading style = %+v", st)
		}
	})
	t.Run("H1 and H3 markers", func(t *testing.T) {
		got := plain(screen("# A\n\n### C", 10))
		if got[0] != "#   A" || got[2] != "### C" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("rule spans the width", func(t *testing.T) {
		got := screen("---", 12)
		if got[0].Plain() != strings.Repeat("─", 12) || got[0][0].Style.FG != theme.Rule {
			t.Errorf("got %q", got[0].Plain())
		}
		ascii := RenderTUI("---", TUIOptions{Width: 12})
		if ascii[0].Plain() != strings.Repeat("-", 12) {
			t.Errorf("ascii rule = %q", ascii[0].Plain())
		}
	})
	t.Run("quote markers and colours, wrapped with marker on every line", func(t *testing.T) {
		got := screen("> one two three four five six", 16)
		for _, l := range got {
			if !strings.HasPrefix(l.Plain(), "> ") {
				t.Errorf("line without quote marker: %q", l.Plain())
			}
			if l[0].Style.FG != theme.QuoteMarker {
				t.Errorf("marker style = %+v", l[0].Style)
			}
		}
		if len(got) < 2 {
			t.Errorf("expected wrapping, got %q", plain(got))
		}
		if got[0][1].Style.FG != theme.QuoteText {
			t.Errorf("quote text style = %+v", got[0][1].Style)
		}
	})
	t.Run("ordered list: number and dot coloured separately, hanging indent", func(t *testing.T) {
		got := screen("1. alpha beta gamma delta", 14)
		first := got[0]
		if first[0].Text != "1" || first[0].Style.FG != theme.ListNumber || first[1].Text != "." || first[1].Style.FG != theme.ListDot {
			t.Errorf("list marker spans = %+v", first[:2])
		}
		for _, l := range got[1:] {
			if !strings.HasPrefix(l.Plain(), "   ") {
				t.Errorf("continuation not indented: %q", l.Plain())
			}
		}
	})
	t.Run("unordered bullet", func(t *testing.T) {
		got := screen("- item", 20)
		if got[0][0].Text != "-" || got[0][0].Style.FG != theme.ListBullet {
			t.Errorf("bullet = %+v", got[0][0])
		}
	})
	t.Run("emphasis carries style", func(t *testing.T) {
		got := screen("**b** *i*", 40)
		var bold, italic bool
		for _, s := range got[0] {
			bold = bold || (s.Text == "b" && s.Style.Bold)
			italic = italic || (s.Text == "i" && s.Style.Italic)
		}
		if !bold || !italic {
			t.Errorf("spans = %+v", got[0])
		}
	})
	t.Run("code block indented, padded, hard-wrapped", func(t *testing.T) {
		got := screen("```\n"+strings.Repeat("x", 30)+"\n```", 20)
		if len(got) != 2 || got[0][0].Style.FG != theme.CodeFG || got[0].Plain() != "  "+strings.Repeat("x", 18) {
			t.Errorf("code = %q", plain(got))
		}
	})
	t.Run("link format and grade colour", func(t *testing.T) {
		got := screen("[docs](https://example.org/d)", 80)
		want := "Link B Considerate: docs -> https://example.org/d"
		if got[0].Plain() != want {
			t.Errorf("link = %q, want %q", got[0].Plain(), want)
		}
		if got[0][0].Style.FG != theme.GradeB {
			t.Errorf("link colour = %s", got[0][0].Style.FG)
		}
	})
	t.Run("no grader means unclassified", func(t *testing.T) {
		got := RenderTUI("https://example.org", TUIOptions{Width: 80})
		if !strings.HasPrefix(got[0].Plain(), "Link ? Unclassified: ") {
			t.Errorf("got %q", got[0].Plain())
		}
	})
}

func TestHTMLRendering(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		want    []string
		notWant []string
	}{
		{"link with badge and rel", "[docs](https://example.org/d)",
			[]string{`<a href="https://example.org/d" rel="nofollow noopener noreferrer ugc">docs</a> <span class="pbc-grade pbc-grade-b" title="Privacy grade B: Considerate">B Considerate</span>`}, nil},
		{"autolink badge", "https://elsewhere.test/a",
			[]string{`<a href="https://elsewhere.test/a" rel="nofollow noopener noreferrer ugc">https://elsewhere.test/a</a> <span class="pbc-grade pbc-grade-unknown"`}, nil},
		{"javascript link removed", "[x](javascript:alert(1))", []string{"x <span class=\"md-link-removed\">"}, []string{"href", "javascript:"}},
		{"raw html escaped", "a <img src=x onerror=alert(1)> b", []string{"a &lt;img src=x onerror=alert(1)&gt; b"}, []string{"<img"}},
		{"html block escaped", "<script>\nalert(1)\n</script>", []string{`<pre class="md-html-source">&lt;script&gt;`}, []string{"<script>"}},
		{"image omitted", "![cat](https://example.org/c.png)", []string{`<span class="md-image-omitted">Image not shown: cat</span>`}, []string{"<img"}},
		{"heading clamped", "##### Deep", []string{"<h3>Deep</h3>"}, []string{"<h5>"}},
		{"code escaped", "```\n<b>\n```", []string{"&lt;b&gt;"}, []string{"<b>"}},
		{"strikethrough", "~~x~~", []string{"<del>x</del>"}, nil},
		{"attribute injection in url", `[x](https://example.org/"onmouseover="a)`, nil, []string{`"onmouseover="`}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RenderHTML(tt.src, fakeGrader{})
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tt.want {
				if !strings.Contains(got, w) {
					t.Errorf("missing %q in:\n%s", w, got)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(got, w) {
					t.Errorf("must not contain %q:\n%s", w, got)
				}
			}
		})
	}
}

func TestSafeURL(t *testing.T) {
	tests := []struct {
		in   string
		ok   bool
		want string
	}{
		{"https://example.org/a?b=c", true, "https://example.org/a?b=c"},
		{"HTTP://example.org", true, "http://example.org"},
		{"mailto:a@example.org", true, "mailto:a@example.org"},
		{"www.example.org", true, "https://www.example.org"},
		{"javascript:alert(1)", false, ""},
		{"data:text/html,x", false, ""},
		{"file:///etc/passwd", false, ""},
		{"/relative", false, ""},
		{"https:///nohost", false, ""},
		{"mailto:", false, ""},
	}
	for _, tt := range tests {
		got, ok := safeURL(tt.in)
		if ok != tt.ok || (ok && got != tt.want) {
			t.Errorf("safeURL(%q) = %q, %v", tt.in, got, ok)
		}
	}
}

func TestSourceLimit(t *testing.T) {
	big := strings.Repeat("a ", MaxSource) // twice the limit
	if lines := RenderTUI(big, TUIOptions{Accessible: true}); len(lines) != 1 || len(lines[0].Plain()) > MaxSource {
		t.Errorf("source not truncated")
	}
}
