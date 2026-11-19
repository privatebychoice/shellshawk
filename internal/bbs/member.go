package bbs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/prefs"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

func fmtTime(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// ---- display settings ----------------------------------------------------

func emphasisOptions(what string) []form.Option {
	return []form.Option{
		{Value: "default", Label: "Terminal type default"},
		{Value: string(theme.EmphSGR), Label: "Real " + what},
		{Value: string(theme.EmphColor), Label: "Highlight colour"},
		{Value: string(theme.EmphUnderline), Label: "Underline"},
		{Value: string(theme.EmphNone), Label: "No change"},
	}
}

func (s *session) settings(ctx context.Context) error {
	cur, err := s.h.Prefs.Get(ctx, s.userID)
	if err != nil {
		return err
	}
	var profiles, themes []form.Option
	for _, p := range theme.Profiles {
		profiles = append(profiles, form.Option{Value: p.Name, Label: p.Title + ": " + p.Help})
	}
	for _, th := range s.h.Prefs.Themes().All() {
		themes = append(themes, form.Option{Value: th.Name, Label: th.Title})
	}
	fm := &form.Form{
		Title: "Display settings",
		Intro: "Use Terminal test from the main menu to see what your terminal supports.",
		Fields: []form.Field{
			{Name: "profile", Label: "Terminal type", Kind: form.Choice, Required: true, Options: profiles,
				Help: "Screen reader mode writes text line by line with no colours or screen drawing."},
			{Name: "theme", Label: "Colour theme", Kind: form.Choice, Required: true, Options: themes},
			{Name: "bold", Label: "Show bold text as", Kind: form.Choice, Required: true, Options: emphasisOptions("bold")},
			{Name: "italic", Label: "Show italic text as", Kind: form.Choice, Required: true, Options: emphasisOptions("italic")},
			{Name: "ascii", Label: "Use plain ASCII symbols only", Kind: form.Boolean},
			{Name: "pagesize", Label: "Lines per page in screen reader mode", Kind: form.SingleLine, Subtype: form.Int,
				Required: true, Min: form.Bound(prefs.MinPageSize), Max: form.Bound(prefs.MaxPageSize)},
			{Name: "transitions", Label: "Show transition screens", Kind: form.Boolean,
				Help: "Text art shown when you open a menu item and when you return to the menu. Never shown in screen reader mode."},
		},
	}
	emph := func(e theme.Emphasis) string {
		if e == "" {
			return "default"
		}
		return string(e)
	}
	vals := form.Values{
		"profile": cur.Profile, "theme": cur.Theme, "bold": emph(cur.Bold), "italic": emph(cur.Italic),
		"ascii": strconv.FormatBool(cur.ASCIIOnly), "pagesize": strconv.Itoa(cur.PageSize),
		"transitions": strconv.FormatBool(cur.Transitions),
	}
	v, err := s.Form(ctx, fm, vals, nil)
	if err != nil {
		return err
	}
	unemph := func(v string) theme.Emphasis {
		if v == "default" {
			return ""
		}
		return theme.Emphasis(v)
	}
	size, _ := strconv.Atoi(v["pagesize"])
	next := prefs.Prefs{
		Profile: v["profile"], Theme: v["theme"], Bold: unemph(v["bold"]), Italic: unemph(v["italic"]),
		ASCIIOnly: v["ascii"] == form.True, PageSize: size, Transitions: v["transitions"] == form.True,
	}
	if err := s.h.Prefs.Set(ctx, s.userID, next); err != nil {
		return err
	}
	s.log.Info("display settings changed", "profile", next.Profile, "theme", next.Theme, "transitions", next.Transitions)
	s.openUI(next)
	msg := "Your settings have been saved."
	if s.conn.PTY == nil && next.Profile != theme.ProfileAccessible {
		msg += " Your SSH client did not request a terminal, so this session stays in line mode."
	}
	return tui.Message(ctx, s.ui, s.Title("Display settings"), msg)
}

// ---- SSH keys --------------------------------------------------------------

func (s *session) keys(ctx context.Context) error {
	for {
		keys, err := s.h.Auth.Keys(ctx, s.userID)
		if err != nil {
			return err
		}
		intro := fmt.Sprintf("You have %d of %d keys.", len(keys), auth.MaxKeysPerUser)
		items := []tui.MenuItem{{Value: "list", Label: "View keys"}}
		if len(keys) < auth.MaxKeysPerUser {
			items = append(items, tui.MenuItem{Value: "add", Label: "Add a key"})
		}
		if len(keys) > 0 {
			items = append(items, tui.MenuItem{Value: "remove", Label: "Remove a key"})
		}

		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("SSH keys"), Intro: intro, Items: items})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "list":
			err = s.ui.Show(ctx, keysPage(s.Title("SSH keys"), keys))
		case "add":
			var added bool
			added, err = s.addKeyForm(ctx, "")
			if err == nil && added {
				err = tui.Message(ctx, s.ui, s.Title("SSH keys"), "Key added.")
			}
		case "remove":
			err = s.removeKey(ctx, keys)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func keyName(k auth.Key) string {
	if k.Label != "" {
		return k.Label
	}
	return "unnamed " + k.Type + " key"
}

func keysPage(title string, keys []auth.Key) tui.Page {
	p := tui.Page{Title: title}
	if len(keys) == 0 {
		p.Lines = append(p.Lines, tui.Text("You have no keys. You can add one from this menu, or by logging in with your password."))
	}
	for i, k := range keys {
		p.Lines = append(p.Lines,
			tui.Line{{Text: fmt.Sprintf("%d. %s", i+1, keyName(k)), Style: theme.Style{Bold: true}}},
			tui.Text("   Type: "+k.Type),
			tui.Text("   Fingerprint: "+k.Fingerprint),
			tui.Text("   Added: "+fmtTime(&k.CreatedAt)+", last used: "+fmtTime(k.LastUsedAt)),
			tui.Text(""),
		)
	}
	return p
}

func (s *session) removeKey(ctx context.Context, keys []auth.Key) error {
	var items []tui.MenuItem
	for _, k := range keys {
		items = append(items, tui.MenuItem{Value: strconv.FormatInt(k.ID, 10), Label: keyName(k), Help: k.Fingerprint})
	}
	choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Remove a key"), Intro: "Which key should be removed?", Items: items})
	if err != nil {
		return err
	}
	q := "Remove this key? You will no longer be able to log in with it."
	if len(keys) == 1 {
		q = "This is your only key. After removing it you can only get back in by logging in with your password to add a new key. Remove it?"
	}
	ok, err := tui.Confirm(ctx, s.ui, s.Title("Remove a key"), q)
	if err != nil || !ok {
		return err
	}
	id, _ := strconv.ParseInt(choice, 10, 64)
	if err := s.h.Auth.RemoveKey(ctx, s.userID, id); err != nil {
		return err
	}
	return tui.Message(ctx, s.ui, s.Title("Remove a key"), "Key removed.")
}

// ---- terminal test ---------------------------------------------------------

// termTest shows raw style samples, independent of the user's settings, so
// they can see what their terminal actually renders (docs/DESIGN.md §6.2).
func (s *session) termTest(ctx context.Context) error {
	if s.ui.LineMode() {
		return tui.Message(ctx, s.ui, s.Title("Terminal test"),
			"You are using screen reader (line) mode, which does not use colours or text styles, so there is nothing to test.",
			"To try the full-screen display, change Terminal type in Display settings.")
	}
	sample := func(label, sgr string) tui.Line {
		return tui.Line{{Text: fmt.Sprintf("%-22s", label)}, {Text: "The quick brown fox", SGR: sgr}}
	}
	p := tui.Page{Title: s.Title("Terminal test"), Lines: []tui.Line{
		tui.Text("Each line below uses one text style. Check which ones look different from normal text."),
		tui.Text(""),
		sample("Normal:", "\x1b[0m"),
		sample("Bold:", "\x1b[0;1m"),
		sample("Italic:", "\x1b[0;3m"),
		sample("Underline:", "\x1b[0;4m"),
		sample("Bold and italic:", "\x1b[0;1;3m"),
		tui.Text(""),
	}}
	var c16, c256, tc tui.Line
	c16 = append(c16, tui.Span{Text: fmt.Sprintf("%-22s", "16 colours:")})
	for i := range 16 {
		code := 40 + i
		if i >= 8 {
			code = 100 + i - 8
		}
		c16 = append(c16, tui.Span{Text: "  ", SGR: fmt.Sprintf("\x1b[0;%dm", code)})
	}
	c256 = append(c256, tui.Span{Text: fmt.Sprintf("%-22s", "256 colours:")})
	for i := 16; i < 232; i += 9 {
		c256 = append(c256, tui.Span{Text: " ", SGR: fmt.Sprintf("\x1b[0;48;5;%dm", i)})
	}
	tc = append(tc, tui.Span{Text: fmt.Sprintf("%-22s", "24-bit colour:")})
	for i := range 24 {
		r := 255 - i*10
		b := i * 10
		tc = append(tc, tui.Span{Text: " ", SGR: fmt.Sprintf("\x1b[0;48;2;%d;80;%dm", r, b)})
	}
	p.Lines = append(p.Lines, c16, c256, tc,
		tui.Text(""),
		tui.Line{{Text: fmt.Sprintf("%-22s", "Symbols:")}, {Text: "┌─┐ │ └─┘ ▶ • é 日本", SGR: "\x1b[0m"}},
		tui.Text(""),
		tui.Text("If the 24-bit colour row is not a smooth red-to-blue fade, choose PuTTY or Basic as your terminal type."),
		tui.Text("If italic looks like normal text, set \"Show italic text as\" to Highlight colour or Underline."),
		tui.Text("If the symbols show as boxes or question marks, turn on \"Use plain ASCII symbols only\"."),
	)
	return s.ui.Show(ctx, p)
}
