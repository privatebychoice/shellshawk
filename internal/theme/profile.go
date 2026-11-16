package theme

import (
	"math"
	"strconv"
	"strings"
)

// ColorDepth is how many colours a terminal can show.
type ColorDepth int

const (
	NoColor ColorDepth = iota
	Color16
	Color256
	TrueColor
)

// Emphasis is how bold or italic text is shown.
type Emphasis string

const (
	EmphSGR       Emphasis = "sgr"       // real bold (SGR 1) / italic (SGR 3)
	EmphColor     Emphasis = "color"     // the theme's substitute colour
	EmphUnderline Emphasis = "underline" // underline (SGR 4)
	EmphNone      Emphasis = "none"      // no visual change
)

// ValidEmphasis reports whether e is a known emphasis mode.
func ValidEmphasis(e Emphasis) bool {
	switch e {
	case EmphSGR, EmphColor, EmphUnderline, EmphNone:
		return true
	}
	return false
}

// Profile describes what a terminal can render.
type Profile struct {
	Name    string
	Title   string
	Help    string
	Depth   ColorDepth
	Bold    Emphasis
	Italic  Emphasis
	Unicode bool // box drawing and symbols; false = ASCII only
	// LineMode: no full-screen drawing; output is appended line by line
	// for screen readers (docs/DESIGN.md §6.3).
	LineMode bool
}

// Profile names.
const (
	ProfileModern     = "modern"
	ProfilePutty      = "putty"
	ProfileBasic      = "basic"
	ProfileAccessible = "accessible"
)

// DefaultProfile is used when a user has not chosen one.
const DefaultProfile = ProfileModern

// Profiles are the built-in terminal profiles. PuTTY renders bold, but whether
// it renders italic is unconfirmed, so italic defaults to a substitute colour
// there; users can change both after using the Terminal test screen.
var Profiles = []Profile{
	{Name: ProfileModern, Title: "Modern terminal", Help: "24-bit colour, bold and italic (most current terminals)",
		Depth: TrueColor, Bold: EmphSGR, Italic: EmphSGR, Unicode: true},
	{Name: ProfilePutty, Title: "PuTTY", Help: "256 colours; italic shown as a colour",
		Depth: Color256, Bold: EmphSGR, Italic: EmphColor, Unicode: true},
	{Name: ProfileBasic, Title: "Basic", Help: "16 colours, ASCII only, emphasis shown as colours",
		Depth: Color16, Bold: EmphColor, Italic: EmphColor, Unicode: false},
	{Name: ProfileAccessible, Title: "Screen reader (line mode)", Help: "No colours or screen drawing; text is written line by line",
		Depth: NoColor, Bold: EmphNone, Italic: EmphNone, Unicode: false, LineMode: true},
}

// LookupProfile returns the named profile.
func LookupProfile(name string) (Profile, bool) {
	for _, p := range Profiles {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

// Style is how a span of text is drawn.
type Style struct {
	FG, BG    Token // "" = theme default (fg / bg)
	Bold      bool
	Italic    bool
	Underline bool
}

// Styler renders Styles as SGR sequences for one theme and profile.
type Styler struct {
	Theme   *Theme
	Profile Profile
}

// Reset clears all attributes.
const Reset = "\x1b[0m"

// SGR returns the escape sequence that starts style s, always beginning
// with a reset so styles never leak into each other.
func (st Styler) SGR(s Style) string {
	p := st.Profile
	codes := []string{"0"}
	fg, bg := s.FG, s.BG
	if fg == "" {
		fg = FG
	}
	if bg == "" {
		bg = BG
	}
	underline := s.Underline
	emph := func(on bool, mode Emphasis, sgr string, sub Token) {
		if !on {
			return
		}
		switch mode {
		case EmphSGR:
			codes = append(codes, sgr)
		case EmphColor:
			if s.FG == "" || s.FG == FG {
				fg = sub
			}
		case EmphUnderline:
			underline = true
		}
	}
	emph(s.Bold, p.Bold, "1", BoldColor)
	emph(s.Italic, p.Italic, "3", ItalicColor)
	if underline {
		codes = append(codes, "4")
	}
	if p.Depth != NoColor {
		codes = append(codes, colorCode(st.Theme.Color(fg), p.Depth, false), colorCode(st.Theme.Color(bg), p.Depth, true))
	}
	return "\x1b[" + strings.Join(codes, ";") + "m"
}

func colorCode(c RGB, d ColorDepth, bg bool) string {
	switch d {
	case TrueColor:
		base := "38;2;"
		if bg {
			base = "48;2;"
		}
		return base + strconv.Itoa(int(c.R)) + ";" + strconv.Itoa(int(c.G)) + ";" + strconv.Itoa(int(c.B))
	case Color256:
		base := "38;5;"
		if bg {
			base = "48;5;"
		}
		return base + strconv.Itoa(To256(c))
	default:
		n := To16(c)
		code := 30 + n
		if n >= 8 {
			code = 90 + n - 8
		}
		if bg {
			code += 10
		}
		return strconv.Itoa(code)
	}
}

var cubeLevels = [6]int{0, 95, 135, 175, 215, 255}

func dist2(a RGB, r, g, b int) int {
	dr, dg, db := int(a.R)-r, int(a.G)-g, int(a.B)-b
	return dr*dr + dg*dg + db*db
}

// To256 returns the nearest xterm 256-colour index (cube or grey ramp).
func To256(c RGB) int {
	nearest := func(v uint8) int {
		best, bd := 0, math.MaxInt
		for i, l := range cubeLevels {
			if d := (int(v) - l) * (int(v) - l); d < bd {
				best, bd = i, d
			}
		}
		return best
	}
	ri, gi, bi := nearest(c.R), nearest(c.G), nearest(c.B)
	cube := 16 + 36*ri + 6*gi + bi
	cubeDist := dist2(c, cubeLevels[ri], cubeLevels[gi], cubeLevels[bi])

	avg := (int(c.R) + int(c.G) + int(c.B)) / 3
	gi2 := (avg - 8 + 5) / 10
	gi2 = max(0, min(23, gi2))
	gv := 8 + 10*gi2
	if d := dist2(c, gv, gv, gv); d < cubeDist {
		return 232 + gi2
	}
	return cube
}

// To16 maps a colour to an ANSI colour index (0–15). Nearest-RGB matching
// turns pastel colours grey (e.g. a light red error becomes grey), losing
// their meaning, so saturated colours are mapped by hue — red, yellow,
// green, cyan, blue, magenta, bright if light — and unsaturated ones by
// lightness to black, dark grey, light grey or white. Actual appearance
// depends on the user's terminal palette.
func To16(c RGB) int {
	r, g, b := float64(c.R)/255, float64(c.G)/255, float64(c.B)/255
	hi, lo := max(r, g, b), min(r, g, b)
	if hi < 0.16 || (hi-lo)/hi < 0.25 {
		switch v := (r + g + b) / 3; {
		case v < 0.25:
			return 0
		case v < 0.6:
			return 8
		case v < 0.85:
			return 7
		default:
			return 15
		}
	}
	var h float64 // hue in degrees
	switch d := hi - lo; hi {
	case r:
		h = math.Mod((g-b)/d, 6) * 60
	case g:
		h = ((b-r)/d + 2) * 60
	default:
		h = ((r-g)/d + 4) * 60
	}
	if h < 0 {
		h += 360
	}
	// Sectors centred on red 0°, yellow 60°, green 120°, cyan 180°, blue
	// 240°, magenta 300° → ANSI 1, 3, 2, 6, 4, 5.
	sector := [6]int{1, 3, 2, 6, 4, 5}[int(math.Mod(h+30, 360)/60)]
	if hi > 0.7 {
		return sector + 8
	}
	return sector
}

// Contrast returns the WCAG 2 contrast ratio between two colours (1–21).
func Contrast(a, b RGB) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

func luminance(c RGB) float64 {
	ch := func(v uint8) float64 {
		x := float64(v) / 255
		if x <= 0.03928 {
			return x / 12.92
		}
		return math.Pow((x+0.055)/1.055, 2.4)
	}
	return 0.2126*ch(c.R) + 0.7152*ch(c.G) + 0.0722*ch(c.B)
}
