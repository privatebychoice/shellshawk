package theme

import (
	"strings"
	"testing"
)

func TestBuiltinThemesComplete(t *testing.T) {
	c, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"amber", "classic", "dark", "green", "high-contrast", "light"}
	var got []string
	for _, th := range c.All() {
		got = append(got, th.Name)
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("themes = %v, want %v", got, want)
	}
}

// TestThemeContrast enforces WCAG contrast: 4.5:1 (AA) for text in every
// theme, 7:1 (AAA) in high-contrast, and 3:1 for the decorative rule.
func TestThemeContrast(t *testing.T) {
	c, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	pairs := [][2]Token{{TitleFG, TitleBG}, {FocusFG, FocusBG}, {InputFG, InputBG}, {HeadingFG, HeadingBG}, {CodeFG, CodeBG}}
	onBG := []Token{FG, Muted, Accent, Error, Warn, OK, QuoteMarker, QuoteText, ListBullet, ListNumber, ListDot,
		Link, GradeA, GradeB, GradeC, GradeD, GradeF, GradeUnknown, BoldColor, ItalicColor}
	for _, th := range c.All() {
		t.Run(th.Name, func(t *testing.T) {
			need := 4.5
			if th.Name == "high-contrast" {
				need = 7
			}
			check := func(a, b Token, min float64) {
				if r := Contrast(th.Color(a), th.Color(b)); r < min {
					t.Errorf("%s on %s contrast %.2f < %.1f", a, b, r, min)
				}
			}
			for _, p := range pairs {
				check(p[0], p[1], need)
			}
			for _, tok := range onBG {
				check(tok, BG, need)
			}
			check(Rule, BG, 3)
		})
	}
}

func TestParseRejectsBadThemes(t *testing.T) {
	tests := []struct{ name, json string }{
		{"missing tokens", `{"name":"x","title":"X","colors":{"fg":"#ffffff"}}`},
		{"unknown token", `{"name":"x","title":"X","colors":{"sparkle":"#ffffff"}}`},
		{"bad colour", `{"name":"x","title":"X","colors":{"fg":"white"}}`},
		{"unknown field", `{"name":"x","title":"X","colors":{},"extra":1}`},
		{"no name", `{"title":"X","colors":{}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.json)); err == nil {
				t.Error("Parse() error = nil")
			}
		})
	}
}

func TestColorConversion(t *testing.T) {
	tests := []struct {
		hex   string
		want  int
		want6 int
	}{
		{"#000000", 16, 0},
		{"#ffffff", 231, 15},
		{"#ff0000", 196, 9},
		{"#808080", 244, 8},
		{"#5fd7ff", 81, 14},
	}
	for _, tt := range tests {
		c, _ := ParseHex(tt.hex)
		if got := To256(c); got != tt.want {
			t.Errorf("To256(%s) = %d, want %d", tt.hex, got, tt.want)
		}
		if got := To16(c); got != tt.want6 {
			t.Errorf("To16(%s) = %d, want %d", tt.hex, got, tt.want6)
		}
	}
	if r := Contrast(RGB{0, 0, 0}, RGB{255, 255, 255}); r < 20.9 || r > 21.1 {
		t.Errorf("black/white contrast = %.2f, want 21", r)
	}
}

func TestStylerSGR(t *testing.T) {
	c, _ := Builtin()
	th := c.Get("high-contrast") // fg #ffffff, bg #000000, bold #ffffff, italic #ff80ff
	prof := func(name string) Profile { p, _ := LookupProfile(name); return p }

	tests := []struct {
		name    string
		profile Profile
		style   Style
		want    string
	}{
		{"truecolor default", prof(ProfileModern), Style{}, "\x1b[0;38;2;255;255;255;48;2;0;0;0m"},
		{"truecolor bold italic", prof(ProfileModern), Style{Bold: true, Italic: true}, "\x1b[0;1;3;38;2;255;255;255;48;2;0;0;0m"},
		{"putty italic as colour", prof(ProfilePutty), Style{Italic: true}, "\x1b[0;38;5;213;48;5;16m"},
		{"basic bold as colour, 16 colours", prof(ProfileBasic), Style{Bold: true}, "\x1b[0;97;40m"},
		{"explicit fg wins over substitute", prof(ProfileBasic), Style{FG: Error, Bold: true}, "\x1b[0;91;40m"},
		{"underline emphasis", Profile{Depth: NoColor, Italic: EmphUnderline}, Style{Italic: true}, "\x1b[0;4m"},
		{"no colour profile", prof(ProfileAccessible), Style{Bold: true, FG: Error}, "\x1b[0m"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Styler{Theme: th, Profile: tt.profile}.SGR(tt.style)
			if got != tt.want {
				t.Errorf("SGR = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProfiles(t *testing.T) {
	p, ok := LookupProfile(ProfileAccessible)
	if !ok || !p.LineMode || p.Depth != NoColor {
		t.Errorf("accessible profile = %+v", p)
	}
	if _, ok := LookupProfile(DefaultProfile); !ok {
		t.Error("default profile missing")
	}
	if _, ok := LookupProfile("nope"); ok {
		t.Error("unknown profile found")
	}
}

// TestErrorStaysRedIn16Colours: meaning must survive the 16-colour mapping.
func TestErrorStaysRedIn16Colours(t *testing.T) {
	c, _ := Builtin()
	for _, th := range c.All() {
		if n := To16(th.Color(Error)); n != 1 && n != 9 {
			t.Errorf("%s: error colour %s maps to ANSI %d, want red (1 or 9)", th.Name, th.Color(Error).Hex(), n)
		}
	}
}
