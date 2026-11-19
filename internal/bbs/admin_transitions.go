package bbs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/transition"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// splasher is implemented by the full-screen UI, which can show text art.
type splasher interface {
	Splash(ctx context.Context, text string) error
}

// transition shows the transition screen for a menu item, if one is set
// and the member has not turned them off. Line mode never shows them:
// text art read out by a screen reader is noise. Failures are logged, not
// shown, so a missing transition never blocks the item.
func (s *session) transition(ctx context.Context, target, moment string) error {
	if s.h.Transitions == nil || s.ui == nil || s.ui.LineMode() {
		return nil
	}
	sp, ok := s.ui.(splasher)
	if !ok {
		return nil
	}
	p, err := s.h.Prefs.Get(ctx, s.userID)
	if err != nil {
		s.log.Error("load preferences for a transition", "err", err)
		return nil
	}
	if !p.Transitions {
		return nil
	}
	text, ok, err := s.h.Transitions.Pick(ctx, target, moment)
	if err != nil {
		s.log.Error("pick a transition", "target", target, "moment", moment, "err", err)
		return nil
	}
	if !ok {
		return nil
	}
	s.log.Debug("transition shown", "target", target, "moment", moment)
	return s.splash(ctx, sp, text)
}

// splash shows art, approximated in ASCII if the member's terminal cannot
// show Unicode. Only the session ending is an error.
func (s *session) splash(ctx context.Context, sp splasher, text string) error {
	if !s.unicode {
		text = transition.ASCII(text)
	}
	if err := sp.Splash(ctx, text); err != nil && sessionEnded(err) {
		return err
	}
	return nil
}

// previewArt shows art to an administrator: as a transition screen in
// full-screen mode, or as a page of lines in line mode.
func (s *session) previewArt(ctx context.Context, title, text string) error {
	if sp, ok := s.ui.(splasher); ok && !s.ui.LineMode() {
		return s.splash(ctx, sp, text)
	}
	p := tui.Page{Title: s.Title(title)}
	for _, l := range strings.Split(text, "\n") {
		p.Lines = append(p.Lines, tui.Text(l))
	}
	return s.ui.Show(ctx, p)
}

// adminTransitions is the transition editor.
func (s *session) adminTransitions(ctx context.Context) error {
	for {
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Transitions"),
			Intro: "Transition screens show text art when a member opens a menu item and when they return to the menu. Members can turn them off in Display settings; they are never shown in screen reader mode.",
			Items: []tui.MenuItem{
				{Value: "profiles", Label: "Profiles", Help: "Sets of text files; one is shown each time"},
				{Value: "points", Label: "Where they are shown", Help: "Choose a profile for opening and leaving each menu item"},
			}})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		if choice == "profiles" {
			err = s.transitionProfiles(ctx)
		} else {
			err = s.transitionPoints(ctx)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func profileSummary(p transition.Profile) string {
	if p.Mode == transition.ModeSingle && p.File != "" {
		return fmt.Sprintf("%d file(s), always %s", p.Files, p.File)
	}
	return fmt.Sprintf("%d file(s), a random one each time", p.Files)
}

func (s *session) transitionProfiles(ctx context.Context) error {
	for {
		ps, err := s.h.Transitions.Profiles(ctx)
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		for _, p := range ps {
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(p.ID, 10), Label: p.Slug, Help: profileSummary(p)})
		}
		intro := "Upload text files over SFTP to /text/<profile>/ (a new folder creates a profile), or add a profile and write files here."
		if len(ps) == 0 {
			intro = "There are no profiles yet. " + intro
		}
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Transition profiles"), Intro: intro, Items: items,
			Actions: []tui.Action{{Key: 'a', Value: "add", Label: "Add a profile"}}})
		if err != nil {
			return err
		}
		if choice == "add" {
			err = s.addTransitionProfile(ctx)
		} else {
			id, _ := strconv.ParseInt(choice, 10, 64)
			err = s.transitionProfile(ctx, id)
		}
		if errors.Is(err, transition.ErrNotFound) {
			err = tui.Message(ctx, s.ui, s.Title("Transition profiles"), "That profile no longer exists.")
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

// slugField is the profile name field.
func slugField() form.Field {
	return form.Field{Name: "slug", Label: "Name", Kind: form.SingleLine, Required: true, MaxLen: transition.MaxSlugLen,
		Help:  "Lowercase letters, digits and hyphens. It is also the SFTP folder: /text/<name>/.",
		Check: func(v string) (string, error) { return v, reasonErr(transition.CheckSlug(v)) }}
}

// reasonErr turns a transition error into one whose message is fit to show.
func reasonErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(transition.Reason(err))
}

func (s *session) addTransitionProfile(ctx context.Context) error {
	fm := &form.Form{Title: "Add a transition profile", Fields: []form.Field{slugField()}}
	vals, errs := form.Values{}, form.Errors{}
	for {
		v, err := s.Form(ctx, fm, vals, errs)
		if err != nil {
			return err
		}
		vals = v
		id, err := s.h.Transitions.CreateProfile(ctx, s.userID, v["slug"])
		switch {
		case errors.Is(err, transition.ErrExists), errors.Is(err, transition.ErrInvalid), errors.Is(err, transition.ErrTooMany):
			errs = form.Errors{"slug": reasonErr(err)}
			continue
		case err != nil:
			return err
		}
		return s.transitionProfile(ctx, id)
	}
}

func (s *session) transitionProfile(ctx context.Context, id int64) error {
	for {
		p, err := s.h.Transitions.ProfileByID(ctx, id)
		if err != nil {
			return err
		}
		files, err := s.h.Transitions.Files(ctx, id)
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		for _, f := range files {
			items = append(items, tui.MenuItem{Value: "file:" + f.Name, Label: f.Name,
				Help: fmt.Sprintf("%d bytes, changed %s", f.Size, fmtTime(&f.Updated))})
		}
		intro := fmt.Sprintf("%s. SFTP folder: /text/%s/", profileSummary(p), p.Slug)
		actions := []tui.Action{{Key: 'w', Value: "write", Label: "Write a new file"}, {Key: 's', Value: "settings", Label: "Name and which file to show"}}
		if len(files) > 0 {
			actions = append(actions, tui.Action{Key: 'p', Value: "preview", Label: "Preview"})
		}
		actions = append(actions, tui.Action{Key: 'd', Value: "delete", Label: "Delete this profile"})
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Profile " + p.Slug), Intro: intro, Items: items, Actions: actions})
		if err != nil {
			return err
		}
		switch {
		case choice == "write":
			err = s.writeTransitionFile(ctx, p, "")
		case choice == "settings":
			err = s.transitionProfileSettings(ctx, p, files)
		case choice == "preview":
			var text string
			var ok bool
			if text, ok, err = s.h.Transitions.PickFrom(ctx, id); err == nil && ok {
				err = s.previewArt(ctx, "Preview", text)
			}
		case choice == "delete":
			var yes bool
			yes, err = tui.Confirm(ctx, s.ui, s.Title("Profile "+p.Slug),
				fmt.Sprintf("Delete %s and its %d file(s)? Places that show it go back to the default.", p.Slug, p.Files))
			if err == nil && yes {
				if err = s.h.Transitions.DeleteProfile(ctx, s.userID, id, false); err == nil {
					return tui.Message(ctx, s.ui, s.Title("Transition profiles"), "Profile deleted.")
				}
			}
		default:
			err = s.transitionFile(ctx, p, strings.TrimPrefix(choice, "file:"))
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func (s *session) transitionProfileSettings(ctx context.Context, p transition.Profile, files []transition.File) error {
	opts := []form.Option{{Value: "", Label: "(none)"}}
	for _, f := range files {
		opts = append(opts, form.Option{Value: f.Name, Label: f.Name})
	}
	fm := &form.Form{Title: "Profile " + p.Slug, Fields: []form.Field{
		slugField(),
		{Name: "mode", Label: "Show", Kind: form.Choice, Required: true, Options: []form.Option{
			{Value: transition.ModeRandom, Label: "A random file each time"},
			{Value: transition.ModeSingle, Label: "Always the file chosen below"},
		}},
		{Name: "file", Label: "File to show", Kind: form.Choice, Options: opts, Help: "Used only when the profile always shows one file."},
	}, Check: func(v form.Values) map[string]error {
		if v["mode"] == transition.ModeSingle && v["file"] == "" {
			return map[string]error{"file": errors.New("choose the file to show")}
		}
		return nil
	}}
	vals, errs := form.Values{"slug": p.Slug, "mode": p.Mode, "file": p.File}, form.Errors{}
	for {
		v, err := s.Form(ctx, fm, vals, errs)
		if err != nil {
			return err
		}
		vals = v
		err = s.h.Transitions.UpdateProfile(ctx, s.userID, p.ID, v["slug"], v["mode"], v["file"])
		switch {
		case errors.Is(err, transition.ErrExists):
			errs = form.Errors{"slug": reasonErr(err)}
			continue
		case errors.Is(err, transition.ErrInvalid): // the name was checked by the form; the file was not
			errs = form.Errors{"file": reasonErr(err)}
			continue
		}
		return err
	}
}

// writeTransitionFile writes a new file (name "") or edits an existing one.
func (s *session) writeTransitionFile(ctx context.Context, p transition.Profile, name string) error {
	text := ""
	if name == "" {
		fm := &form.Form{Title: "Write a new file", Fields: []form.Field{{
			Name: "name", Label: "File name", Kind: form.SingleLine, Required: true, MaxLen: transition.MaxNameLen,
			Help:  "Letters, digits, dots, hyphens and underscores, e.g. welcome.txt.",
			Check: func(v string) (string, error) { return v, reasonErr(transition.CheckName(v)) },
		}}}
		vals, errs := form.Values{}, form.Errors{}
		for {
			v, err := s.Form(ctx, fm, vals, errs)
			if err != nil {
				return err
			}
			vals = v
			if _, _, err := s.h.Transitions.ReadFile(ctx, p.ID, v["name"]); err == nil {
				errs = form.Errors{"name": errors.New("a file with that name exists; choose it from the profile to edit it")}
				continue
			}
			name = v["name"]
			break
		}
	} else {
		var err error
		if text, _, err = s.h.Transitions.ReadFile(ctx, p.ID, name); err != nil {
			return err
		}
	}
	for {
		edited, err := s.ui.Edit(ctx, tui.EditRequest{Title: s.Title(p.Slug + "/" + name), Text: text, MaxLen: transition.MaxFileBytes,
			Preview: func(t string) tui.Page {
				pg := tui.Page{Title: s.Title("Preview")}
				for _, l := range strings.Split(t, "\n") {
					pg.Lines = append(pg.Lines, tui.Text(l))
				}
				return pg
			}})
		if err != nil {
			return err
		}
		text = edited
		err = s.h.Transitions.SaveFile(ctx, s.userID, p.ID, name, []byte(edited))
		if errors.Is(err, transition.ErrInvalid) || errors.Is(err, transition.ErrTooMany) {
			if err := tui.Message(ctx, s.ui, s.Title(p.Slug+"/"+name), transition.Reason(err), "The file was not saved."); err != nil {
				return err
			}
			if errors.Is(err, transition.ErrTooMany) {
				return nil
			}
			continue
		}
		if err != nil {
			return err
		}
		return tui.Message(ctx, s.ui, s.Title(p.Slug+"/"+name), "File saved.")
	}
}

func (s *session) transitionFile(ctx context.Context, p transition.Profile, name string) error {
	for {
		text, _, err := s.h.Transitions.ReadFile(ctx, p.ID, name)
		if errors.Is(err, transition.ErrNotFound) {
			return nil // deleted meanwhile, e.g. over SFTP
		}
		if err != nil {
			return err
		}
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title(p.Slug + "/" + name), Items: []tui.MenuItem{
			{Value: "view", Label: "View", Help: "As members see it"},
			{Value: "edit", Label: "Edit"},
			{Value: "delete", Label: "Delete"},
		}})
		if err != nil {
			return err
		}
		switch choice {
		case "view":
			err = s.previewArt(ctx, p.Slug+"/"+name, text)
		case "edit":
			err = s.writeTransitionFile(ctx, p, name)
		case "delete":
			var yes bool
			if yes, err = tui.Confirm(ctx, s.ui, s.Title(p.Slug+"/"+name), "Delete "+name+"?"); err == nil && yes {
				return s.h.Transitions.DeleteFile(ctx, s.userID, p.ID, name)
			}
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

// pointValue and describePoint translate a transition point's setting to
// a form value and a description.
func pointValue(pt transition.Point) string {
	switch {
	case !pt.Set:
		return "inherit"
	case pt.ProfileID == 0:
		return "none"
	}
	return strconv.FormatInt(pt.ProfileID, 10)
}

func describePoint(pt transition.Point, names map[int64]string, isDefault bool) string {
	switch {
	case !pt.Set && isDefault, pt.Set && pt.ProfileID == 0:
		return "nothing"
	case !pt.Set:
		return "the default"
	}
	return names[pt.ProfileID]
}

func (s *session) transitionPoints(ctx context.Context) error {
	for {
		ps, err := s.h.Transitions.Profiles(ctx)
		if err != nil {
			return err
		}
		names := map[int64]string{}
		for _, p := range ps {
			names[p.ID] = p.Slug
		}
		pts, err := s.h.Transitions.Points(ctx)
		if err != nil {
			return err
		}
		labels := map[string]string{transition.DefaultTarget: "Default for every item"}
		targets := []string{transition.DefaultTarget}
		for _, d := range s.h.MenuDefaults() {
			targets = append(targets, d.Target)
			labels[d.Target] = d.Label
		}
		var items []tui.MenuItem
		for _, t := range targets {
			isDefault := t == transition.DefaultTarget
			items = append(items, tui.MenuItem{Value: t, Label: labels[t], Help: fmt.Sprintf("Opening: %s. Leaving: %s.",
				describePoint(pts[transition.PointKey(t, transition.Enter)], names, isDefault),
				describePoint(pts[transition.PointKey(t, transition.Exit)], names, isDefault))})
		}
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Where transitions are shown"),
			Intro: "Choose an item to set the profile shown when a member opens it and when they return to the menu. Items set to the default use the first entry.",
			Items: items})
		if err != nil {
			return err
		}
		if err := s.editTransitionPoint(ctx, choice, labels[choice], ps, pts); err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func (s *session) editTransitionPoint(ctx context.Context, target, label string, ps []transition.Profile, pts map[string]transition.Point) error {
	isDefault := target == transition.DefaultTarget
	var opts []form.Option
	if !isDefault {
		opts = append(opts, form.Option{Value: "inherit", Label: "The default"})
	}
	opts = append(opts, form.Option{Value: "none", Label: "Nothing"})
	for _, p := range ps {
		opts = append(opts, form.Option{Value: strconv.FormatInt(p.ID, 10), Label: p.Slug + " (" + profileSummary(p) + ")"})
	}
	fm := &form.Form{Title: label, Fields: []form.Field{
		{Name: transition.Enter, Label: "When opening it", Kind: form.Choice, Required: true, Options: opts},
		{Name: transition.Exit, Label: "When returning to the menu", Kind: form.Choice, Required: true, Options: opts},
	}}
	vals := form.Values{}
	for _, m := range []string{transition.Enter, transition.Exit} {
		vals[m] = pointValue(pts[transition.PointKey(target, m)])
		if isDefault && vals[m] == "inherit" {
			vals[m] = "none"
		}
	}
	v, err := s.Form(ctx, fm, vals, nil)
	if err != nil {
		return err
	}
	for _, m := range []string{transition.Enter, transition.Exit} {
		if v[m] == vals[m] {
			continue
		}
		var c transition.Choice
		switch v[m] {
		case "inherit":
			c.Inherit = true
		case "none":
		default:
			c.ProfileID, _ = strconv.ParseInt(v[m], 10, 64)
		}
		if err := s.h.Transitions.SetPoint(ctx, s.userID, target, m, c, s.h.itemExists); err != nil {
			if errors.Is(err, transition.ErrNotFound) {
				return tui.Message(ctx, s.ui, s.Title(label), "That profile was deleted meanwhile. Nothing was changed.")
			}
			return err
		}
	}
	return tui.Message(ctx, s.ui, s.Title(label), "Saved.")
}
