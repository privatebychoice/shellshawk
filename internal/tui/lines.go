package tui

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// maxInputLen bounds a single line of input.
const maxInputLen = 64 * 1024

// Lines is the line-by-line UI. Nothing is ever redrawn: output is appended
// like a conversation, which screen readers follow well. No colour is used.
type Lines struct {
	t        *term.Terminal
	pageSize int
	warned   bool // shown the no-PTY password warning
}

// NewLines returns a line-mode UI. pageSize is the number of lines shown
// before pausing (0 = default 20).
func NewLines(t *term.Terminal, pageSize int) *Lines {
	if pageSize <= 0 {
		pageSize = 20
	}
	return &Lines{t: t, pageSize: pageSize}
}

// LineMode implements UI.
func (u *Lines) LineMode() bool { return true }

// Close implements UI.
func (u *Lines) Close() error { return u.t.Flush() }

// echo reports whether we must echo input. With a PTY the client is in raw
// mode and shows nothing unless we echo; without one, its own terminal
// echoes and edits lines.
func (u *Lines) echo() bool { return u.t.PTY }

func (u *Lines) println(s string) {
	u.t.WriteString(term.Sanitize(s, false) + "\r\n")
}

func (u *Lines) heading(title string) {
	u.t.WriteString("\r\n")
	u.println("Screen: " + title)
}

// readLine reads one line. secret suppresses echo.
func (u *Lines) readLine(ctx context.Context, prompt string, secret bool) (string, error) {
	u.t.WriteString(term.Sanitize(prompt, false))
	if err := u.t.Flush(); err != nil {
		return "", err
	}
	var buf []rune
	echo := u.echo() && !secret
	for {
		ev, err := u.t.Next(ctx)
		if err != nil {
			return "", err
		}
		switch ev.Key {
		case term.KeyRune:
			if len(buf) < maxInputLen {
				buf = append(buf, ev.Rune)
				if echo {
					u.t.WriteString(string(ev.Rune))
				}
			}
		case term.KeyPaste:
			for _, r := range term.Sanitize(ev.Text, false) {
				if len(buf) < maxInputLen {
					buf = append(buf, r)
					if echo {
						u.t.WriteString(string(r))
					}
				}
			}
		case term.KeyBackspace:
			if n := len(buf); n > 0 {
				w := term.RuneWidth(buf[n-1])
				buf = buf[:n-1]
				if echo && w > 0 {
					u.t.WriteString(strings.Repeat("\b", w) + strings.Repeat(" ", w) + strings.Repeat("\b", w))
				}
			}
		case term.KeyCtrl:
			switch ev.Rune {
			case 'c':
				if u.echo() {
					u.t.WriteString("\r\n")
				}
				u.println("Cancelled.")
				return "", ErrCancelled
			case 'd':
				if len(buf) == 0 {
					return "", io.EOF
				}
			case 'u':
				if echo {
					w := term.Width(string(buf))
					u.t.WriteString(strings.Repeat("\b", w) + strings.Repeat(" ", w) + strings.Repeat("\b", w))
				}
				buf = buf[:0]
			}
		case term.KeyEsc:
			if u.echo() {
				u.t.WriteString("\r\n")
			}
			u.println("Cancelled.")
			return "", ErrCancelled
		case term.KeyEnter:
			if u.echo() {
				u.t.WriteString("\r\n")
			}
			return string(buf), nil
		}
		if err := u.t.Flush(); err != nil {
			return "", err
		}
	}
}

// Show implements UI: prints the page, pausing every pageSize lines.
func (u *Lines) Show(ctx context.Context, p Page) error {
	u.heading(p.Title)
	shown := 0
	for i, l := range p.Lines {
		u.println(l.Plain())
		shown++
		if shown >= u.pageSize && i < len(p.Lines)-1 {
			ans, err := u.readLine(ctx, "More: press Enter to continue, or type q and press Enter to skip the rest. ", false)
			if err != nil {
				return err
			}
			if strings.EqualFold(strings.TrimSpace(ans), "q") {
				break
			}
			shown = 0
		}
	}
	_, err := u.readLine(ctx, "End of screen. Press Enter to continue. ", false)
	return err
}

// Choose implements UI.
func (u *Lines) Choose(ctx context.Context, m Menu) (string, error) {
	u.heading(m.Title)
	if m.Intro != "" {
		u.println(m.Intro)
	}
	u.println(fmt.Sprintf("%d choices:", len(m.Items)))
	for i, it := range m.Items {
		line := fmt.Sprintf("%d. %s", i+1, it.Label)
		if it.Help != "" {
			line += ". " + it.Help
		}
		u.println(line)
	}
	for {
		ans, err := u.readLine(ctx, fmt.Sprintf("Enter a number from 1 to %d, or q to go back: ", len(m.Items)), false)
		if err != nil {
			return "", err
		}
		ans = strings.TrimSpace(ans)
		if strings.EqualFold(ans, "q") {
			return "", ErrCancelled
		}
		if n, err := strconv.Atoi(ans); err == nil && n >= 1 && n <= len(m.Items) {
			return m.Items[n-1].Value, nil
		}
		u.println(fmt.Sprintf("Error: %q is not a number from 1 to %d.", ans, len(m.Items)))
	}
}

// Form implements UI: asks for each field in turn, re-asking until valid.
func (u *Lines) Form(ctx context.Context, fm *form.Form, values form.Values, errs form.Errors) (form.Values, error) {
	vals := form.Values{}
	for k, v := range values {
		vals[k] = v
	}
	u.heading(fm.Title)
	if fm.Intro != "" {
		u.println(fm.Intro)
	}
	u.println("Press Ctrl-C at any prompt to cancel.")

	for {
		if len(errs) > 0 {
			u.println(fmt.Sprintf("Please correct %d field(s):", len(errs)))
		}
		for i := range fm.Fields {
			f := &fm.Fields[i]
			if len(errs) > 0 && errs[f.Name] == nil {
				continue
			}
			v, err := u.askField(ctx, f, vals[f.Name], errs[f.Name])
			if err != nil {
				return nil, err
			}
			vals[f.Name] = v
		}
		out, verrs := fm.Validate(vals)
		if len(verrs) == 0 {
			return out, nil
		}
		errs = verrs
	}
}

// askField prompts for one field until its value validates.
func (u *Lines) askField(ctx context.Context, f *form.Field, current string, prevErr error) (string, error) {
	secret := f.Subtype == form.Password
	label := f.Label
	if c := f.Constraints(); c != "" {
		label += " (" + c + ")"
	}
	u.t.WriteString("\r\n")
	u.println("Field: " + label)
	if f.Help != "" {
		u.println("Help: " + f.Help)
	}
	if prevErr != nil {
		u.println("Error: " + prevErr.Error())
	}
	if secret && !u.echo() && !u.warned {
		u.println("Warning: your SSH client did not request a terminal, so what you type will be visible on your screen.")
		u.warned = true
	}
	if current != "" && !secret {
		u.println("Current value: " + displayValue(f, current) + ". Press Enter to keep it.")
	}

	for {
		raw, inputErr, err := u.readRaw(ctx, f, current, secret)
		if err != nil {
			return "", err
		}
		if inputErr != nil {
			u.println("Error: " + inputErr.Error())
			continue
		}
		v, verr := f.Validate(raw)
		if verr == nil {
			return v, nil
		}
		u.println("Error: " + f.Label + " " + verr.Error() + ".")
	}
}

// readRaw reads the raw input for f. inputErr reports input that could not
// be interpreted (e.g. an out-of-range choice number); err ends the form.
func (u *Lines) readRaw(ctx context.Context, f *form.Field, current string, secret bool) (raw string, inputErr, err error) {
	switch f.Kind {
	case form.MultiLine:
		u.println("Type or paste the text. When finished, type a single period on a line by itself and press Enter.")
		var lines []string
		for {
			l, err := u.readLine(ctx, "", false)
			if err != nil {
				return "", nil, err
			}
			if strings.TrimSpace(l) == "." {
				break
			}
			lines = append(lines, l)
		}
		if len(lines) == 0 && current != "" {
			return current, nil, nil
		}
		return strings.Join(lines, "\n"), nil, nil

	case form.Choice:
		for i, o := range f.Options {
			line := fmt.Sprintf("%d. %s", i+1, o.Label)
			if isChosen(current, o.Value) {
				line += " (currently selected)"
			}
			u.println(line)
		}
		prompt := fmt.Sprintf("Enter a number from 1 to %d: ", len(f.Options))
		if f.Multi {
			prompt = "Enter numbers separated by commas"
			if !f.Required {
				prompt += ", or none to choose nothing"
			}
			prompt += ": "
		}
		ans, err := u.readLine(ctx, prompt, false)
		if err != nil {
			return "", nil, err
		}
		if strings.TrimSpace(ans) == "" {
			return current, nil, nil
		}
		// An empty answer keeps the current choice, so "none" is how a
		// multiple choice is cleared (validation still applies Required).
		if f.Multi && strings.EqualFold(strings.TrimSpace(ans), "none") {
			return "", nil, nil
		}
		var picked []string
		for _, p := range strings.Split(ans, ",") {
			n, err := strconv.Atoi(strings.TrimSpace(p))
			if err != nil || n < 1 || n > len(f.Options) {
				return "", fmt.Errorf("%q is not a number from 1 to %d.", strings.TrimSpace(p), len(f.Options)), nil
			}
			picked = append(picked, f.Options[n-1].Value)
		}
		return strings.Join(picked, ","), nil, nil

	case form.Boolean:
		cur := "no"
		if current == form.True {
			cur = "yes"
		}
		ans, err := u.readLine(ctx, fmt.Sprintf("%s? Type yes or no (currently %s): ", f.Label, cur), false)
		if err != nil {
			return "", nil, err
		}
		if strings.TrimSpace(ans) == "" {
			return current, nil, nil
		}
		return ans, nil, nil
	}

	prompt := f.Label + ": "
	if secret {
		prompt = f.Label + " (typing is hidden): "
	}
	ans, err := u.readLine(ctx, prompt, secret)
	if err != nil {
		return "", nil, err
	}
	if ans == "" && current != "" && !secret {
		return current, nil, nil
	}
	return ans, nil, nil
}

func isChosen(current, v string) bool {
	for _, c := range strings.Split(current, ",") {
		if c == v {
			return true
		}
	}
	return false
}

// displayValue renders a stored value for "current value" messages.
func displayValue(f *form.Field, v string) string {
	switch f.Kind {
	case form.Choice:
		var labels []string
		for _, o := range f.Options {
			if isChosen(v, o.Value) {
				labels = append(labels, o.Label)
			}
		}
		return strings.Join(labels, ", ")
	case form.Boolean:
		if v == form.True {
			return "yes"
		}
		return "no"
	case form.MultiLine:
		n := strings.Count(v, "\n") + 1
		return fmt.Sprintf("%d line(s) of text", n)
	}
	return v
}

// ReadLine prompts for and reads one line of visible input.
func (u *Lines) ReadLine(ctx context.Context, prompt string) (string, error) {
	return u.readLine(ctx, prompt, false)
}
