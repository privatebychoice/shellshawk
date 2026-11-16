// Package tui provides the BBS user interface primitives — pages, menus and
// forms — with two interchangeable implementations:
//
//   - Screen: full-screen, themed, keyboard driven.
//   - Lines: line by line with no screen drawing, for screen readers and
//     for clients that did not allocate a terminal (docs/DESIGN.md §6.3).
//
// Application screens are written once against UI and work in both.
package tui

import (
	"context"
	"errors"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/theme"
)

// ErrCancelled is returned when the user backs out of a menu or form.
var ErrCancelled = errors.New("cancelled")

// Span is a run of text in one style. Text is sanitised before display, so
// it may contain user data.
type Span struct {
	Text  string
	Style theme.Style
	// SGR, if set, is a raw escape sequence used by the full-screen UI
	// instead of Style (e.g. the terminal test). Never user data.
	SGR string
}

// Line is one line of spans.
type Line []Span

// Text returns an unstyled line.
func Text(s string) Line { return Line{{Text: s}} }

// Styled returns a single-span line.
func Styled(s string, st theme.Style) Line { return Line{{Text: s, Style: st}} }

// Plain joins the line's text.
func (l Line) Plain() string {
	var b strings.Builder
	for _, s := range l {
		b.WriteString(s.Text)
	}
	return b.String()
}

// Page is a titled block of text.
type Page struct {
	Title string
	Lines []Line
}

// MenuItem is one menu choice.
type MenuItem struct {
	Value string // returned by Choose
	Label string
	Help  string
}

// Menu is a list of choices.
type Menu struct {
	Title string
	Intro string
	Items []MenuItem
}

// UI is implemented by Screen and Lines.
type UI interface {
	// Show displays a page and returns when the user dismisses it.
	Show(ctx context.Context, p Page) error
	// Choose returns the Value of the chosen item, or ErrCancelled.
	Choose(ctx context.Context, m Menu) (string, error)
	// Form collects values until they all validate, or returns
	// ErrCancelled. values pre-fills fields; errs shows errors from a
	// previous attempt (e.g. "username taken") and focuses those fields.
	Form(ctx context.Context, fm *form.Form, values form.Values, errs form.Errors) (form.Values, error)
	// LineMode reports whether this is the line-by-line UI.
	LineMode() bool
	// Close restores the terminal.
	Close() error
}

// Confirm asks a yes/no question.
func Confirm(ctx context.Context, ui UI, title, question string) (bool, error) {
	v, err := ui.Choose(ctx, Menu{Title: title, Intro: question, Items: []MenuItem{
		{Value: "no", Label: "No"},
		{Value: "yes", Label: "Yes"},
	}})
	if errors.Is(err, ErrCancelled) {
		return false, nil
	}
	return v == "yes", err
}

// Message shows a short single-paragraph page.
func Message(ctx context.Context, ui UI, title string, lines ...string) error {
	p := Page{Title: title}
	for _, l := range lines {
		p.Lines = append(p.Lines, Text(l))
	}
	return ui.Show(ctx, p)
}
