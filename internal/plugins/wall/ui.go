package wall

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// ago describes how long ago t was, roughly.
func ago(now, t time.Time) string {
	return roughly(now.Sub(t)) + " ago"
}

// roughly describes a duration in the largest whole unit.
func roughly(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour")
	}
	return plural(int(d/(24*time.Hour)), "day")
}

func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// wallPage shows every line with its author and age. Emphasis is shown as
// bold and italic; screen-reader line mode shows the words without markers.
func (p *Plugin) wallPage(s plugin.Session, entries []Entry) tui.Page {
	pg := tui.Page{Title: s.Title("Wall")}
	if len(entries) == 0 {
		pg.Lines = append(pg.Lines, tui.Text("The wall is empty. Be the first to write a line."))
	}
	now := p.now()
	for _, e := range entries {
		l := tui.Line{{Text: e.Username + ": ", Style: theme.Style{FG: theme.Accent, Bold: true}}}
		l = append(l, Spans(e.Text)...)
		l = append(l, tui.Span{Text: " (" + ago(now, e.UpdatedAt) + ")", Style: theme.Style{FG: theme.Muted}})
		pg.Lines = append(pg.Lines, l)
	}
	return pg
}

func (p *Plugin) run(ctx context.Context, s plugin.Session) error {
	show := true
	for {
		entries, err := p.Entries(ctx)
		if err != nil {
			return err
		}
		set, err := s.Permissions(ctx)
		if err != nil {
			return err
		}
		var mine *Entry
		for i := range entries {
			if entries[i].UserID == s.UserID() {
				mine = &entries[i]
			}
		}
		if show {
			if err := s.UI().Show(ctx, p.wallPage(s, entries)); err != nil {
				return err
			}
		}
		show = true

		var items []tui.MenuItem
		intro := fmt.Sprintf("%d line(s) on the wall.", len(entries))
		if set.Has(PermWrite) {
			if mine == nil {
				items = append(items, tui.MenuItem{Value: "write", Label: "Write my line"})
			} else {
				intro += " Your line expires in " + roughly(mine.ExpiresAt.Sub(p.now())) + "; editing it renews it."
				items = append(items, tui.MenuItem{Value: "write", Label: "Edit my line"},
					tui.MenuItem{Value: "remove", Label: "Remove my line"})
			}
		}
		if set.Has(PermModerate) && len(entries) > 0 {
			items = append(items, tui.MenuItem{Value: "moderate", Label: "Remove a member's line"})
		}
		items = append(items, tui.MenuItem{Value: "show", Label: "Show the wall again"}, tui.MenuItem{Value: "back", Label: "Back"})
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Wall"), Intro: intro, Items: items})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "write":
			err = p.writeForm(ctx, s, mine)
		case "remove":
			ok, cerr := tui.Confirm(ctx, s.UI(), s.Title("Wall"), "Remove your line from the wall?")
			if cerr != nil || !ok {
				err = cerr
				break
			}
			err = p.Remove(ctx, s.UserID(), s.UserID())
		case "moderate":
			err = p.moderate(ctx, s, entries)
		}
		if errors.Is(err, tui.ErrCancelled) {
			err = nil
		}
		if errors.Is(err, perm.ErrForbidden) || errors.Is(err, ErrNotFound) {
			err = tui.Message(ctx, s.UI(), s.Title("Wall"), "That could not be done: "+err.Error()+".")
		}
		if err != nil {
			return err
		}
	}
}

// writeForm asks for the member's line, showing validation problems until
// the line is saved or the member cancels.
func (p *Plugin) writeForm(ctx context.Context, s plugin.Session, mine *Entry) error {
	days := roughly(p.Expiry(ctx))
	fm := &form.Form{Title: "My wall line", Fields: []form.Field{{
		Name: "line", Label: "Your line", Kind: form.SingleLine, Required: true, MaxLen: MaxLine,
		Help: "One line for everyone to see. Use **bold** and *italic* for emphasis. It disappears " + days + " after your last edit.",
	}}}
	vals := form.Values{}
	if mine != nil {
		vals["line"] = mine.Text
	}
	var errs form.Errors
	for {
		v, err := s.Form(ctx, fm, vals, errs)
		if err != nil {
			return err
		}
		err = p.Set(ctx, s.UserID(), v["line"])
		if !errors.Is(err, ErrInvalid) {
			return err
		}
		vals, errs = v, form.Errors{"line": errors.New(strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))}
	}
}

// moderate lets a moderator remove someone's line.
func (p *Plugin) moderate(ctx context.Context, s plugin.Session, entries []Entry) error {
	var items []tui.MenuItem
	for _, e := range entries {
		items = append(items, tui.MenuItem{Value: strconv.FormatInt(e.UserID, 10), Label: e.Username + ": " + Plain(e.Text)})
	}
	items = append(items, tui.MenuItem{Value: "back", Label: "Back"})
	choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Remove a member's line"), Items: items})
	if err != nil || choice == "back" {
		return err
	}
	owner, _ := strconv.ParseInt(choice, 10, 64)
	ok, err := tui.Confirm(ctx, s.UI(), s.Title("Wall"), "Remove this line from the wall?")
	if err != nil || !ok {
		return err
	}
	return p.Remove(ctx, s.UserID(), owner)
}
