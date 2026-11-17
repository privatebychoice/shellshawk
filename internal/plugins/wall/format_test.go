package wall

import "testing"

func TestFormat(t *testing.T) {
	tests := []struct {
		name, in, html, plain string
	}{
		{"plain", "Hello wall", "Hello wall", "Hello wall"},
		{"bold", "**Back** soon", "<strong>Back</strong> soon", "Back soon"},
		{"italic star", "out *Monday*", "out <em>Monday</em>", "out Monday"},
		{"italic underscore", "_quietly_ away", "<em>quietly</em> away", "quietly away"},
		{"mixed", "Back *Monday*, **no calls**", "Back <em>Monday</em>, <strong>no calls</strong>", "Back Monday, no calls"},
		{"bold italic", "***both***", "<strong><em>both</em></strong>", "both"},
		{"italic inside bold", "**very *much* so**", "<strong>very </strong><strong><em>much</em></strong><strong> so</strong>", "very much so"},
		{"unclosed bold", "**open", "**open", "**open"},
		{"unclosed italic", "2 * 3", "2 * 3", "2 * 3"},
		{"snake_case kept", "my_var_name", "my_var_name", "my_var_name"},
		{"escaped marker", `\*not italic\*`, "*not italic*", "*not italic*"},
		{"escaped backslash", `a\\b`, `a\b`, `a\b`},
		{"html escaped", "<b>x</b> & **<i>**", "&lt;b&gt;x&lt;/b&gt; &amp; <strong>&lt;i&gt;</strong>", "<b>x</b> & <i>"},
		{"links stay text", "[x](https://example.com) # h", "[x](https://example.com) # h", "[x](https://example.com) # h"},
		{"empty pair", "a****b", "ab", "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HTML(tt.in); got != tt.html {
				t.Errorf("HTML = %q, want %q", got, tt.html)
			}
			if got := Plain(tt.in); got != tt.plain {
				t.Errorf("Plain = %q, want %q", got, tt.plain)
			}
		})
	}
	spans := Spans("a **b** *c*")
	if len(spans) != 4 || !spans[1].Style.Bold || !spans[3].Style.Italic || spans[0].Style.Bold {
		t.Errorf("Spans = %+v", spans)
	}
}
