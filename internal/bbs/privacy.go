package bbs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/privacy"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// freshLogin is how recent the key login must be to request erasure
// (docs/DESIGN.md §5.2: "requires re-authentication by public key").
const freshLogin = 15 * time.Minute

func (s *session) privacyMenu(ctx context.Context) error {
	for {
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Privacy and profile"), Items: []tui.MenuItem{
			{Value: "profile", Label: "Edit my profile", Help: "Full name, email, phone and status message"},
			{Value: "visibility", Label: "Who can see what", Help: "Choose who sees each detail and who can message you"},
			{Value: "export", Label: "Download my data", Help: "Everything stored about you, over SFTP"},
			{Value: "erase", Label: "Erase my account"},
		}})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "profile":
			err = s.editProfile(ctx)
		case "visibility":
			err = s.editVisibility(ctx)
		case "export":
			err = tui.Message(ctx, s.ui, s.Title("Download my data"),
				"Connect with any SFTP client using your SSH key, as the same user you log in with.",
				"The folder /me/export contains everything stored about you: account.json for your account and profile, and one folder per feature (messages, posts, contacts, votes, chat).",
				"The files are created when you download them, so they are always up to date.")
		case "erase":
			err = s.eraseAccount(ctx)
		}
		if errors.Is(err, privacy.ErrInvalid) {
			err = tui.Message(ctx, s.ui, s.Title("Privacy and profile"), tui.Sentence(err, privacy.ErrInvalid))
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func (s *session) editProfile(ctx context.Context) error {
	p, err := s.h.Privacy.Get(ctx, s.userID)
	if err != nil {
		return err
	}
	fm := &form.Form{
		Title: "Edit my profile",
		Intro: "Everything is optional. Choose who can see each detail under Who can see what.",
		Fields: []form.Field{
			{Name: "name", Label: "Full name", Kind: form.SingleLine, MaxLen: privacy.MaxFullName},
			{Name: "email", Label: "Email", Kind: form.SingleLine, Subtype: form.Email},
			{Name: "phone", Label: "Phone", Kind: form.SingleLine, Subtype: form.Phone},
			{Name: "status", Label: "Status message", Kind: form.SingleLine, MaxLen: privacy.MaxStatus},
		},
	}
	v, err := s.Form(ctx, fm, form.Values{"name": p.FullName, "email": p.Email, "phone": p.Phone, "status": p.Status}, nil)
	if err != nil {
		return err
	}
	p.FullName, p.Email, p.Phone, p.Status = v["name"], v["email"], v["phone"], v["status"]
	if err := s.h.Privacy.Update(ctx, s.userID, p); err != nil {
		return err
	}
	return tui.Message(ctx, s.ui, s.Title("Privacy and profile"), "Your profile has been saved.")
}

func (s *session) editVisibility(ctx context.Context) error {
	p, err := s.h.Privacy.Get(ctx, s.userID)
	if err != nil {
		return err
	}
	opts := []form.Option{
		{Value: string(privacy.Public), Label: privacy.LevelLabel(privacy.Public)},
		{Value: string(privacy.Friends), Label: privacy.LevelLabel(privacy.Friends) + " (members who have you as a contact too)"},
		{Value: string(privacy.NoOne), Label: privacy.LevelLabel(privacy.NoOne)},
	}
	fm := &form.Form{Title: "Who can see what", Intro: "Administrators can see your email address for account recovery; each time they do, it is recorded."}
	vals := form.Values{}
	for _, f := range privacy.Fields {
		fm.Fields = append(fm.Fields, form.Field{Name: string(f.Field), Label: f.Label, Kind: form.Choice, Required: true, Options: opts})
		vals[string(f.Field)] = string(p.Visibility[f.Field])
	}
	v, err := s.Form(ctx, fm, vals, nil)
	if err != nil {
		return err
	}
	for _, f := range privacy.Fields {
		p.Visibility[f.Field] = privacy.Level(v[string(f.Field)])
	}
	if err := s.h.Privacy.Update(ctx, s.userID, p); err != nil {
		return err
	}
	return tui.Message(ctx, s.ui, s.Title("Privacy and profile"), "Your privacy settings have been saved.")
}

func (s *session) eraseAccount(ctx context.Context) error {
	if s.loginStale() {
		return tui.Message(ctx, s.ui, s.Title("Erase my account"),
			fmt.Sprintf("For your safety, erasing your account needs a fresh login. Disconnect, log in again with your SSH key and come straight here within %d minutes.", int(freshLogin.Minutes())))
	}
	u, err := s.h.Auth.UserByID(ctx, s.userID)
	if err != nil {
		return err
	}
	grace := s.h.Privacy.Grace()
	when := "immediately"
	if grace > 0 {
		when = fmt.Sprintf("after %d days", int(grace.Hours()/24))
	}
	if err := tui.Message(ctx, s.ui, s.Title("Erase my account"),
		"Your account will be locked as soon as you confirm, and erased "+when+".",
		"Until then an administrator can cancel the request if you change your mind. After that it cannot be undone.",
		"Erasing removes your keys, password, email, profile, contacts, received messages and settings, and unlinks your poll votes.",
		"Messages you sent stay with the people who received them, shown as from a former member.",
		"You choose next whether your posts and chat messages are deleted or kept anonymously.",
		"Download your data first if you want a copy: see Download my data."); err != nil {
		return err
	}
	fm := &form.Form{
		Title: "Erase my account",
		Fields: []form.Field{
			{Name: "content", Label: "Your posts and chat messages", Kind: form.Choice, Required: true, Options: []form.Option{
				{Value: "delete", Label: "Delete them"},
				{Value: "keep", Label: "Keep them, shown as from a former member"},
			}},
			{Name: "confirm", Label: "Type your username to confirm", Kind: form.SingleLine, Required: true, MaxLen: 32,
				Check: func(v string) (string, error) {
					if auth.NormalizeUsername(v) != u.Username {
						return "", errors.New("does not match your username")
					}
					return v, nil
				}},
		},
	}
	v, err := s.Form(ctx, fm, nil, nil)
	if err != nil {
		return err
	}
	ok, err := tui.Confirm(ctx, s.ui, s.Title("Erase my account"), "Lock your account now and erase it "+when+"?")
	if err != nil || !ok {
		return err
	}
	e, err := s.h.Privacy.RequestErasure(ctx, s.userID, v["content"] == "delete")
	if errors.Is(err, privacy.ErrLastAdminErase) {
		return tui.Message(ctx, s.ui, s.Title("Erase my account"), tui.Sentence(err))
	}
	if err != nil {
		return err
	}
	if err := tui.Message(ctx, s.ui, s.Title("Erase my account"),
		"Your account is locked and will be erased on "+e.EraseAfter.UTC().Format("2006-01-02 15:04 UTC")+".",
		"To cancel, contact an administrator before then. You will now be logged out."); err != nil {
		return err
	}
	return errLogout
}

// webLoginCode shows a one-time code for the web interface.
func (s *session) webLoginCode(ctx context.Context) error {
	code, expires, err := s.h.WebLogin.NewCode(ctx, s.userID)
	if err != nil {
		return err
	}
	u, err := s.h.Auth.UserByID(ctx, s.userID)
	if err != nil {
		return err
	}
	return tui.Message(ctx, s.ui, s.Title("Web login code"),
		"Your code is:",
		"",
		"    "+code,
		"",
		fmt.Sprintf("On the website's login page, enter your username (%s) and this code. It works once and expires at %s. Getting a new code cancels this one.",
			u.Username, expires.UTC().Format("15:04 UTC")))
}
