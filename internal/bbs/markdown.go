package bbs

import (
	"context"
	_ "embed"
	"errors"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/markdown"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

//go:embed guide.md
var guideMarkdown string

// Markdown renders src for this session's interface and width.
func (s *session) Markdown(title, src string) tui.Page {
	return s.MarkdownAt(title, src, markdown.UnderTitle)
}

// MarkdownAt is Markdown with "#" headings shown at level.
func (s *session) MarkdownAt(title, src string, level int) tui.Page {
	o := markdown.TUIOptions{Accessible: s.ui.LineMode(), Unicode: s.unicode, Grader: s.h.Grader, HeadingLevel: level}
	if !o.Accessible {
		o.Width = max(s.t.Size().Cols-2, 20)
	}
	return markdown.Page(title, src, o)
}

// markdownGuide shows the built-in guide and lets the user preview their own
// markdown.
func (s *session) markdownGuide(ctx context.Context) error {
	for {
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Markdown"), Items: []tui.MenuItem{
			{Value: "guide", Label: "Markdown guide", Help: "Every supported style, rendered"},
			{Value: "try", Label: "Try it", Help: "Type some markdown and see how it looks"},
			{Value: "back", Label: "Back"},
		}})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "guide":
			err = s.ui.Show(ctx, s.Markdown(s.Title("Markdown guide"), guideMarkdown))
		case "try":
			err = s.markdownPreview(ctx)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func (s *session) markdownPreview(ctx context.Context) error {
	fm := &form.Form{
		Title: "Try markdown",
		Fields: []form.Field{{
			Name: "text", Label: "Markdown", Kind: form.MultiLine, Subtype: form.Markdown, Required: true,
			MaxLen: 8000, Help: "Nothing you type here is saved.",
		}},
	}
	vals := form.Values{}
	for {
		v, err := s.Form(ctx, fm, vals, nil)
		if err != nil {
			return err
		}
		vals = v
		if err := s.ui.Show(ctx, s.Markdown(s.Title("Preview"), v["text"])); err != nil {
			return err
		}
		again, err := tui.Confirm(ctx, s.ui, s.Title("Preview"), "Edit the text and preview again?")
		if err != nil || !again {
			return err
		}
	}
}
