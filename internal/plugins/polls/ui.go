package polls

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

func message(err error) string {
	switch {
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrClosed), errors.Is(err, ErrBadVote), errors.Is(err, ErrNotFound):
		return err.Error() + "."
	case errors.Is(err, perm.ErrForbidden):
		return "You do not have permission to do that."
	}
	return ""
}

func (p *Plugin) run(ctx context.Context, s plugin.Session) error {
	for {
		set, err := s.Permissions(ctx)
		if err != nil {
			return err
		}
		open, err := p.List(ctx, true)
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		for _, pl := range open {
			label := pl.Question
			if pl.Pinned {
				label = "Pinned: " + label
			}
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(pl.ID, 10), Label: label})
		}
		items = append(items, tui.MenuItem{Value: "closed", Label: "Closed polls and results"})
		if set.Has(PermCreate) {
			items = append(items, tui.MenuItem{Value: "new", Label: "Create a poll"})
		}
		items = append(items, tui.MenuItem{Value: "back", Label: "Back"})
		intro := fmt.Sprintf("%d open poll(s).", len(open))
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Polls"), Intro: intro, Items: items})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "closed":
			err = p.closedList(ctx, s)
		case "new":
			err = p.createForm(ctx, s)
		default:
			id, _ := strconv.ParseInt(choice, 10, 64)
			err = p.Run(ctx, s, id)
		}
		if msg := message(err); msg != "" {
			err = tui.Message(ctx, s.UI(), s.Title("Polls"), msg)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func (p *Plugin) closedList(ctx context.Context, s plugin.Session) error {
	closed, err := p.List(ctx, false)
	if err != nil {
		return err
	}
	if len(closed) == 0 {
		return tui.Message(ctx, s.UI(), s.Title("Closed polls"), "There are no closed polls.")
	}
	var items []tui.MenuItem
	for _, pl := range closed {
		items = append(items, tui.MenuItem{Value: strconv.FormatInt(pl.ID, 10), Label: pl.Question})
	}
	choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Closed polls"), Items: items})
	if err != nil {
		return err
	}
	id, _ := strconv.ParseInt(choice, 10, 64)
	return p.Run(ctx, s, id)
}

func (p *Plugin) createForm(ctx context.Context, s plugin.Session) error {
	_, err := p.CreateForm(ctx, s, "")
	return err
}

// CreateForm asks the member for a new poll and creates it in context (""
// for the Polls menu, or e.g. "conferences:post:42" for an attached poll).
// It returns the poll's ID, or tui.ErrCancelled.
func (p *Plugin) CreateForm(ctx context.Context, s plugin.Session, pollContext string) (int64, error) {
	set, err := s.Permissions(ctx)
	if err != nil {
		return 0, err
	}
	fields := []form.Field{
		{Name: "q", Label: "Question", Kind: form.SingleLine, Required: true, MaxLen: MaxQuestion},
		{Name: "options", Label: "Options", Kind: form.MultiLine, Required: true, MaxLen: MaxOptions * (MaxOption + 1),
			Help: fmt.Sprintf("One option per line, %d to %d options.", MinOptions, MaxOptions)},
		{Name: "multi", Label: "Members may choose more than one option", Kind: form.Boolean},
		{Name: "named", Label: "Show who voted for what (otherwise votes are anonymous)", Kind: form.Boolean},
		{Name: "days", Label: "Close automatically after this many days (0 = stay open)", Kind: form.SingleLine, Subtype: form.Int,
			Required: true, Min: form.Bound(0), Max: form.Bound(MaxOpenDays)},
	}
	if set.Has(PermManage) && pollContext == "" {
		fields = append(fields, form.Field{Name: "pinned", Label: "Pin to the top of the Polls menu", Kind: form.Boolean})
	}
	fm := &form.Form{Title: "Create a poll", Fields: fields}
	vals, errs := form.Values{"days": "7"}, form.Errors{}
	for {
		v, err := s.Form(ctx, fm, vals, errs)
		if err != nil {
			return 0, err
		}
		vals = v
		days, _ := strconv.Atoi(v["days"])
		id, err := p.Create(ctx, Spec{
			Question: v["q"], Options: strings.Split(v["options"], "\n"),
			Multi: v["multi"] == form.True, Named: v["named"] == form.True,
			ClosesIn: time.Duration(days) * 24 * time.Hour, Pinned: v["pinned"] == form.True, CreatorID: s.UserID(),
			Context: pollContext,
		})
		switch {
		case err == nil:
			return id, tui.Message(ctx, s.UI(), s.Title("Polls"), "Poll created.")
		case errors.Is(err, ErrInvalid):
			field := "options"
			if strings.Contains(err.Error(), "question") {
				field = "q"
			} else if strings.Contains(err.Error(), "days") {
				field = "days"
			}
			errs = form.Errors{field: err}
		default:
			return 0, err
		}
	}
}

// Run shows one poll: the vote form while it is open and the member may
// vote, then the results (when the member may see them), then actions.
// Conferences uses it for polls attached to posts.
func (p *Plugin) Run(ctx context.Context, s plugin.Session, id int64) error {
	for {
		pl, err := p.Get(ctx, s.UserID(), id)
		if err != nil {
			return err
		}
		set, err := s.Permissions(ctx)
		if err != nil {
			return err
		}
		closed := pl.Closed(p.now())
		var items []tui.MenuItem
		if !closed && set.Has(PermVote) {
			label := "Vote"
			if len(pl.MyVotes) > 0 {
				label = "Change your vote"
			}
			items = append(items, tui.MenuItem{Value: "vote", Label: label})
		}
		if p.CanSeeResults(pl, s.UserID(), set) {
			items = append(items, tui.MenuItem{Value: "results", Label: "Results"})
		}
		if p.canManage(ctx, s.UserID(), pl, false) == nil {
			if !closed {
				items = append(items, tui.MenuItem{Value: "close", Label: "Close this poll"})
			}
			items = append(items, tui.MenuItem{Value: "delete", Label: "Delete this poll"})
		}
		if pl.Context == "" && set.Has(PermManage) {
			if pl.Pinned {
				items = append(items, tui.MenuItem{Value: "unpin", Label: "Unpin"})
			} else {
				items = append(items, tui.MenuItem{Value: "pin", Label: "Pin to the top"})
			}
		}
		items = append(items, tui.MenuItem{Value: "back", Label: "Back"})
		choice, err := s.UI().Choose(ctx, tui.Menu{Title: s.Title("Poll"), Intro: describe(pl, closed), Items: items})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "vote":
			err = p.voteForm(ctx, s, pl)
			if err == nil {
				err = p.showResults(ctx, s, id)
			}
		case "results":
			err = p.showResults(ctx, s, id)
		case "close":
			err = p.Close(ctx, s.UserID(), id)
		case "pin", "unpin":
			err = p.SetPinned(ctx, s.UserID(), id, choice == "pin")
		case "delete":
			ok, cerr := tui.Confirm(ctx, s.UI(), s.Title("Poll"), "Delete this poll and all its votes?")
			if cerr != nil || !ok {
				err = cerr
				break
			}
			if err = p.Delete(ctx, s.UserID(), id); err == nil {
				return tui.Message(ctx, s.UI(), s.Title("Polls"), "Poll deleted.")
			}
		}
		if msg := message(err); msg != "" {
			err = tui.Message(ctx, s.UI(), s.Title("Poll"), msg)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func describe(pl Poll, closed bool) string {
	var b strings.Builder
	b.WriteString(pl.Question)
	if pl.Multi {
		b.WriteString(" You may choose more than one option.")
	}
	if pl.Anonymous {
		b.WriteString(" Votes are anonymous.")
	} else {
		b.WriteString(" Votes are not anonymous: everyone can see who voted for what.")
	}
	switch {
	case closed:
		b.WriteString(" This poll is closed.")
	case pl.ClosesAt != nil:
		b.WriteString(" Closes " + pl.ClosesAt.UTC().Format("2006-01-02 15:04 UTC") + ".")
	}
	if len(pl.MyVotes) > 0 {
		b.WriteString(" You have voted.")
	}
	fmt.Fprintf(&b, " Created by %s.", pl.Creator)
	return b.String()
}

func (p *Plugin) voteForm(ctx context.Context, s plugin.Session, pl Poll) error {
	var opts []form.Option
	for _, o := range pl.Options {
		opts = append(opts, form.Option{Value: strconv.FormatInt(o.ID, 10), Label: o.Label})
	}
	help := "Votes are anonymous."
	if !pl.Anonymous {
		help = "This poll is not anonymous: everyone will see your choice."
	}
	fm := &form.Form{Title: pl.Question, Fields: []form.Field{{
		Name: "choice", Label: "Your vote", Kind: form.Choice, Multi: pl.Multi, Required: true, Options: opts, Help: help,
	}}}
	var cur []string
	for _, id := range pl.MyVotes {
		cur = append(cur, strconv.FormatInt(id, 10))
	}
	v, err := s.Form(ctx, fm, form.Values{"choice": strings.Join(cur, ",")}, nil)
	if err != nil {
		return err
	}
	var ids []int64
	for _, c := range strings.Split(v["choice"], ",") {
		id, _ := strconv.ParseInt(c, 10, 64)
		ids = append(ids, id)
	}
	return p.Vote(ctx, s.UserID(), pl.ID, ids)
}

// showResults draws a bar per option. Counts and percentages are always
// written out, so the bars are never the only way to read the result.
func (p *Plugin) showResults(ctx context.Context, s plugin.Session, id int64) error {
	pl, err := p.Get(ctx, s.UserID(), id)
	if err != nil {
		return err
	}
	set, err := s.Permissions(ctx)
	if err != nil {
		return err
	}
	if !p.CanSeeResults(pl, s.UserID(), set) {
		return tui.Message(ctx, s.UI(), s.Title("Results"), "Results are shown after you vote or when the poll closes.")
	}
	total := 0
	for _, o := range pl.Options {
		total += o.Votes
	}
	page := tui.Page{Title: s.Title("Results")}
	page.Lines = append(page.Lines, tui.Text(pl.Question),
		tui.Text(fmt.Sprintf("%d vote(s) from %d member(s).", total, pl.Voters)), tui.Text(""))
	lineMode := s.UI().LineMode()
	for i, o := range pl.Options {
		pct := 0
		if total > 0 {
			pct = o.Votes * 100 / total
		}
		mine := ""
		if slices.Contains(pl.MyVotes, o.ID) {
			mine = " (your vote)"
		}
		page.Lines = append(page.Lines, tui.Text(fmt.Sprintf("Option %d, %s: %d vote(s), %d percent%s.", i+1, o.Label, o.Votes, pct, mine)))
		if !lineMode {
			bar := strings.Repeat("#", pct/4)
			page.Lines = append(page.Lines, tui.Line{{Text: "  " + bar, Style: theme.Style{FG: theme.Accent}}})
		}
		if !pl.Anonymous && len(o.Voters) > 0 {
			page.Lines = append(page.Lines, tui.Text("  Voted: "+strings.Join(o.Voters, ", ")))
		}
	}
	return s.UI().Show(ctx, page)
}
