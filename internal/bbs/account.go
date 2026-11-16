package bbs

import (
	"context"
	"errors"
	"fmt"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/prefs"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// Field names shared by the registration and add-key forms.
const (
	fUsername = "username"
	fPassword = "password"
	fConfirm  = "confirm"
	fEmail    = "email"
	fKey      = "key"
	fKeyLabel = "label"
)

func keyFields() []form.Field {
	return []form.Field{
		{
			Name: fKey, Label: "SSH public key", Kind: form.MultiLine, Subtype: form.PublicKey, Required: true,
			Help: "Paste the contents of your public key file, for example id_ed25519.pub. Never paste your private key.",
			Check: func(v string) (string, error) {
				if _, _, err := auth.ParsePublicKey(v); err != nil {
					return "", err
				}
				return v, nil
			},
		},
		{Name: fKeyLabel, Label: "Key name", Kind: form.SingleLine, MaxLen: 64, Help: "Optional, to tell your keys apart (for example: laptop)."},
	}
}

func registrationForm(inviteUser string) *form.Form {
	fields := []form.Field{
		{
			Name: fUsername, Label: "Username", Kind: form.SingleLine, Required: true, MinLen: 3, MaxLen: 32,
			Help: "Lowercase letters, digits, '_' or '-', starting with a letter. This is how others see you.",
			Check: func(v string) (string, error) {
				v = auth.NormalizeUsername(v)
				return v, auth.ValidateUsername(v, inviteUser)
			},
		},
		{
			Name: fPassword, Label: "Password", Kind: form.SingleLine, Subtype: form.Password, Required: true,
			MinLen: auth.MinPasswordLen, MaxLen: auth.MaxPasswordLen,
			Help: "Only used to add a new SSH key if you lose yours. A long passphrase is easiest to remember.",
		},
		{Name: fConfirm, Label: "Repeat password", Kind: form.SingleLine, Subtype: form.Password, Required: true},
		{
			Name: fEmail, Label: "Email", Kind: form.SingleLine, Subtype: form.Email,
			Help: "Optional. Hidden from other members unless you choose to show it.",
		},
	}
	return &form.Form{
		Title:  "Create your account",
		Intro:  "Your invite code is valid. Fill in the form to create your account. You will log in with your SSH key.",
		Fields: append(fields, keyFields()...),
		Check: func(v form.Values) map[string]error {
			if v[fPassword] != v[fConfirm] {
				return map[string]error{fConfirm: errors.New("does not match the password")}
			}
			return nil
		},
	}
}

// fieldForError maps an account-service error to the form field it concerns.
func fieldForError(err error) string {
	switch {
	case errors.Is(err, auth.ErrUsernameTaken), errors.Is(err, auth.ErrUsernameInvalid), errors.Is(err, auth.ErrUsernameReserved):
		return fUsername
	case errors.Is(err, auth.ErrPasswordPolicy):
		return fPassword
	case errors.Is(err, auth.ErrEmailInvalid):
		return fEmail
	case errors.Is(err, auth.ErrKeyInvalid), errors.Is(err, auth.ErrKeyInUse):
		return fKey
	}
	return ""
}

// register runs the invite registration wizard.
func (s *session) register(ctx context.Context) error {
	accessible, err := s.askAccessible(ctx)
	if err != nil {
		return err
	}
	p := prefs.Default()
	if accessible {
		p.Profile = theme.ProfileAccessible
	}
	s.openUI(p)

	fm := registrationForm(s.h.Auth.InviteUser())
	vals, errs := form.Values{}, form.Errors{}
	for {
		v, err := s.form(ctx, fm, vals, errs)
		if errors.Is(err, tui.ErrCancelled) {
			return tui.Message(ctx, s.ui, s.title("Registration"), "Registration cancelled. Your invite code has not been used.")
		}
		if err != nil {
			return err
		}
		vals = v
		u, err := s.h.Auth.Register(ctx, s.conn.Identity.InviteCode, auth.Registration{
			Username: v[fUsername], Password: v[fPassword], Email: v[fEmail], PublicKey: v[fKey], KeyLabel: v[fKeyLabel],
		})
		if err == nil {
			s.userID = u.ID
			s.log = s.log.With("user_id", u.ID)
			if err := s.h.Prefs.Set(ctx, u.ID, p); err != nil {
				s.log.Error("save preferences after registration", "err", err)
			}
			return s.registered(ctx, u)
		}
		if f := fieldForError(err); f != "" {
			errs = form.Errors{f: err}
			continue
		}
		if errors.Is(err, auth.ErrInviteInvalid) {
			return tui.Message(ctx, s.ui, s.title("Registration"), "Sorry, this invite code is no longer valid. It may have expired or been used.")
		}
		s.log.Error("registration failed", "err", err)
		return tui.Message(ctx, s.ui, s.title("Registration"), "Sorry, something went wrong creating your account. Please try again later.")
	}
}

func (s *session) registered(ctx context.Context, u auth.User) error {
	lines := []string{fmt.Sprintf("Your account %q has been created.", u.Username)}
	if u.Status == auth.StatusPending {
		lines = append(lines, "A moderator needs to approve it before you can use the BBS. You can log in to check its status.")
	}
	lines = append(lines,
		"",
		fmt.Sprintf("Next time, connect as user %q using the SSH key you just added.", u.Username),
		"If you ever lose your key, connect with your username and password to add a new one.",
	)
	return tui.Message(ctx, s.ui, s.title("Welcome"), lines...)
}

// addKeyLogin is the screen for a password login: add a key, nothing else.
func (s *session) addKeyLogin(ctx context.Context) error {
	keys, err := s.h.Auth.Keys(ctx, s.userID)
	if err != nil {
		return err
	}
	if len(keys) >= auth.MaxKeysPerUser {
		return tui.Message(ctx, s.ui, s.title("Add SSH key"),
			fmt.Sprintf("Your account already has the maximum of %d keys.", auth.MaxKeysPerUser),
			"Log in with one of them and remove a key you no longer use first.")
	}
	added, err := s.addKeyForm(ctx, "You logged in with your password, which can only be used to add an SSH key.")
	if err != nil || !added {
		return err
	}
	return tui.Message(ctx, s.ui, s.title("Add SSH key"), "Your key has been added. Disconnect and log in again using it.")
}

// addKeyForm collects and adds one key. It reports whether a key was added.
func (s *session) addKeyForm(ctx context.Context, intro string) (bool, error) {
	fm := &form.Form{Title: "Add SSH key", Intro: intro, Fields: keyFields()}
	vals, errs := form.Values{}, form.Errors{}
	for {
		v, err := s.form(ctx, fm, vals, errs)
		if errors.Is(err, tui.ErrCancelled) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		vals = v
		_, err = s.h.Auth.AddKey(ctx, s.userID, v[fKey], v[fKeyLabel])
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, auth.ErrKeyLimit):
			return false, tui.Message(ctx, s.ui, s.title("Add SSH key"), err.Error()+".")
		case fieldForError(err) != "":
			errs = form.Errors{fieldForError(err): err}
		default:
			s.log.Error("add key failed", "err", err)
			return false, tui.Message(ctx, s.ui, s.title("Add SSH key"), "Sorry, the key could not be added. Please try again later.")
		}
	}
}
