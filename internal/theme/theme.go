// Package theme defines colour themes and terminal profiles, and turns them
// into terminal escape sequences (docs/DESIGN.md §6.2, §9).
//
// A theme is a set of semantic colour tokens given as 24-bit RGB; 256- and
// 16-colour values are derived. A profile describes what the user's terminal
// can render. The same tokens are used by the web interface as CSS custom
// properties.
package theme

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
)

// Token names a semantic colour.
type Token string

// Theme tokens. Every theme must define all of them.
const (
	FG           Token = "fg"
	BG           Token = "bg"
	Muted        Token = "muted"
	Accent       Token = "accent"
	TitleFG      Token = "title.fg"
	TitleBG      Token = "title.bg"
	Error        Token = "error"
	Warn         Token = "warn"
	OK           Token = "ok"
	FocusFG      Token = "focus.fg"
	FocusBG      Token = "focus.bg"
	InputFG      Token = "input.fg"
	InputBG      Token = "input.bg"
	HeadingFG    Token = "heading.fg"
	HeadingBG    Token = "heading.bg"
	QuoteMarker  Token = "quote.marker"
	QuoteText    Token = "quote.text"
	ListBullet   Token = "list.bullet"
	ListNumber   Token = "list.number"
	ListDot      Token = "list.dot"
	CodeFG       Token = "code.fg"
	CodeBG       Token = "code.bg"
	Rule         Token = "rule"
	Link         Token = "link"
	GradeA       Token = "grade.a"
	GradeB       Token = "grade.b"
	GradeC       Token = "grade.c"
	GradeD       Token = "grade.d"
	GradeF       Token = "grade.f"
	GradeUnknown Token = "grade.unknown"
	BoldColor    Token = "bold"   // substitute for bold where SGR 1 is unavailable
	ItalicColor  Token = "italic" // substitute for italic where SGR 3 is unavailable
)

// AllTokens lists every token a theme must define.
var AllTokens = []Token{
	FG, BG, Muted, Accent, TitleFG, TitleBG, Error, Warn, OK, FocusFG, FocusBG,
	InputFG, InputBG, HeadingFG, HeadingBG, QuoteMarker, QuoteText, ListBullet,
	ListNumber, ListDot, CodeFG, CodeBG, Rule, Link, GradeA, GradeB, GradeC,
	GradeD, GradeF, GradeUnknown, BoldColor, ItalicColor,
}

// RGB is a 24-bit colour.
type RGB struct{ R, G, B uint8 }

// ParseHex parses "#rrggbb".
func ParseHex(s string) (RGB, error) {
	if len(s) != 7 || s[0] != '#' {
		return RGB{}, fmt.Errorf("theme: colour %q is not #rrggbb", s)
	}
	v, err := strconv.ParseUint(s[1:], 16, 32)
	if err != nil {
		return RGB{}, fmt.Errorf("theme: colour %q is not #rrggbb", s)
	}
	return RGB{uint8(v >> 16), uint8(v >> 8), uint8(v)}, nil
}

// Hex returns "#rrggbb".
func (c RGB) Hex() string { return fmt.Sprintf("#%02x%02x%02x", c.R, c.G, c.B) }

// Theme is a named set of token colours.
type Theme struct {
	Name   string
	Title  string
	Dark   bool
	Colors map[Token]RGB
}

// Color returns the colour for t (black if undefined, which Validate prevents).
func (th *Theme) Color(t Token) RGB { return th.Colors[t] }

type themeFile struct {
	Name   string            `json:"name"`
	Title  string            `json:"title"`
	Dark   bool              `json:"dark"`
	Colors map[string]string `json:"colors"`
}

// Parse decodes and validates a theme JSON document.
func Parse(b []byte) (*Theme, error) {
	var tf themeFile
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tf); err != nil {
		return nil, fmt.Errorf("theme: %w", err)
	}
	if tf.Name == "" || tf.Title == "" {
		return nil, fmt.Errorf("theme: name and title are required")
	}
	th := &Theme{Name: tf.Name, Title: tf.Title, Dark: tf.Dark, Colors: map[Token]RGB{}}
	for k, v := range tf.Colors {
		if !slices.Contains(AllTokens, Token(k)) {
			return nil, fmt.Errorf("theme %s: unknown token %q", tf.Name, k)
		}
		c, err := ParseHex(v)
		if err != nil {
			return nil, fmt.Errorf("theme %s: %s: %w", tf.Name, k, err)
		}
		th.Colors[Token(k)] = c
	}
	for _, t := range AllTokens {
		if _, ok := th.Colors[t]; !ok {
			return nil, fmt.Errorf("theme %s: missing token %q", tf.Name, t)
		}
	}
	return th, nil
}

//go:embed themes/*.json
var builtinFS embed.FS

// DefaultTheme is used when a user has not chosen one.
const DefaultTheme = "classic"

// Catalog holds the available themes.
type Catalog struct {
	themes map[string]*Theme
	order  []string
}

// Builtin returns a catalog of the embedded themes.
func Builtin() (*Catalog, error) {
	c := &Catalog{themes: map[string]*Theme{}}
	entries, err := fs.ReadDir(builtinFS, "themes")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		b, err := builtinFS.ReadFile(path.Join("themes", e.Name()))
		if err != nil {
			return nil, err
		}
		th, err := Parse(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if err := c.Add(th); err != nil {
			return nil, err
		}
	}
	if c.Get(DefaultTheme) == nil {
		return nil, fmt.Errorf("theme: default theme %q missing", DefaultTheme)
	}
	return c, nil
}

// Add registers a theme.
func (c *Catalog) Add(th *Theme) error {
	if _, dup := c.themes[th.Name]; dup {
		return fmt.Errorf("theme: duplicate theme %q", th.Name)
	}
	c.themes[th.Name] = th
	c.order = append(c.order, th.Name)
	slices.Sort(c.order)
	return nil
}

// Get returns the named theme or nil.
func (c *Catalog) Get(name string) *Theme { return c.themes[name] }

// All returns the themes sorted by name.
func (c *Catalog) All() []*Theme {
	out := make([]*Theme, 0, len(c.order))
	for _, n := range c.order {
		out = append(out, c.themes[n])
	}
	return out
}
