package bbs

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/settings"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// admin is the minimal administration menu: approvals and invites. The full
// admin menu (users, groups, plugin settings) arrives with stage 6.
func (s *session) admin(ctx context.Context) error {
	for {
		set, err := s.h.Perms.Permissions(ctx, s.userID)
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		if set.Has(perm.UsersApprove) {
			items = append(items, tui.MenuItem{Value: "pending", Label: "Accounts awaiting approval"})
		}
		if set.Has(perm.InviteCreate) {
			items = append(items, tui.MenuItem{Value: "invite", Label: "Create an invite"})
		}
		if set.Has(perm.InviteCreate) || set.Has(perm.InviteManage) {
			items = append(items, tui.MenuItem{Value: "invites", Label: "View or revoke invites"})
		}
		if set.Has(perm.SettingsManage) {
			items = append(items, tui.MenuItem{Value: "branding", Label: "Branding", Help: "The BBS name shown in every title"})
		}
		items = append(items, tui.MenuItem{Value: "back", Label: "Back"})

		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.title("Administration"), Items: items})
		if errors.Is(err, tui.ErrCancelled) || choice == "back" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "pending":
			err = s.pendingAccounts(ctx)
		case "invite":
			err = s.createInvite(ctx)
		case "invites":
			err = s.manageInvites(ctx)
		case "branding":
			err = s.branding(ctx)
		}
		if errors.Is(err, perm.ErrForbidden) {
			err = tui.Message(ctx, s.ui, s.title("Administration"), "You do not have permission to do that.")
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

func (s *session) pendingAccounts(ctx context.Context) error {
	for {
		users, err := s.h.Auth.PendingUsers(ctx, s.userID)
		if err != nil {
			return err
		}
		if len(users) == 0 {
			return tui.Message(ctx, s.ui, s.title("Approvals"), "No accounts are waiting for approval.")
		}
		var items []tui.MenuItem
		for _, u := range users {
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(u.ID, 10), Label: u.Username, Help: "Registered " + fmtTime(&u.CreatedAt)})
		}
		choice, err := s.ui.Choose(ctx, tui.Menu{
			Title: s.title("Approvals"), Intro: fmt.Sprintf("%d account(s) waiting. Choose one to approve or reject.", len(users)), Items: items,
		})
		if err != nil {
			return err
		}
		id, _ := strconv.ParseInt(choice, 10, 64)
		action, err := s.ui.Choose(ctx, tui.Menu{Title: s.title("Approvals"), Items: []tui.MenuItem{
			{Value: "approve", Label: "Approve", Help: "The account can use the BBS"},
			{Value: "reject", Label: "Reject", Help: "The account and its keys are deleted"},
			{Value: "back", Label: "Back"},
		}})
		if errors.Is(err, tui.ErrCancelled) || action == "back" {
			continue
		}
		if err != nil {
			return err
		}
		if action == "approve" {
			err = s.h.Auth.Approve(ctx, s.userID, id)
		} else {
			ok, cerr := tui.Confirm(ctx, s.ui, s.title("Approvals"), "Reject and delete this account?")
			if cerr != nil || !ok {
				continue
			}
			err = s.h.Auth.Reject(ctx, s.userID, id)
		}
		switch {
		case errors.Is(err, perm.ErrForbidden):
			err = tui.Message(ctx, s.ui, s.title("Approvals"), "You cannot act on this account: it would receive permissions you do not have.")
		case errors.Is(err, auth.ErrNotPending):
			err = tui.Message(ctx, s.ui, s.title("Approvals"), "This account is no longer pending.")
		}
		if err != nil {
			return err
		}
	}
}

func (s *session) createInvite(ctx context.Context) error {
	groups, err := s.h.Perms.Groups(ctx)
	if err != nil {
		return err
	}
	var opts []form.Option
	for _, g := range groups {
		opts = append(opts, form.Option{Value: g.Name, Label: g.Name})
	}
	fm := &form.Form{
		Title: "Create an invite",
		Fields: []form.Field{
			{Name: "uses", Label: "Number of accounts it can create", Kind: form.SingleLine, Subtype: form.Int, Required: true,
				Min: form.Bound(1), Max: form.Bound(auth.MaxInviteUses)},
			{Name: "days", Label: "Days until it expires", Kind: form.SingleLine, Subtype: form.Int, Required: true,
				Min: form.Bound(1), Max: form.Bound(auth.MaxInviteTTL.Hours() / 24)},
			{Name: "approval", Label: "New accounts need approval", Kind: form.Boolean},
			{Name: "groups", Label: "Groups", Kind: form.Choice, Multi: true, Options: opts,
				Help: "Groups new accounts join. None selected means member. You can only choose groups whose permissions you have."},
			{Name: "note", Label: "Note for administrators", Kind: form.SingleLine, MaxLen: 200, Help: "Optional, e.g. who it is for. Never shown to the invitee."},
		},
	}
	vals := form.Values{"uses": "1", "days": "7", "approval": form.False}
	var errs form.Errors
	for {
		v, err := s.form(ctx, fm, vals, errs)
		if err != nil {
			return err
		}
		vals = v
		uses, _ := strconv.Atoi(v["uses"])
		days, _ := strconv.Atoi(v["days"])
		var gs []string
		if v["groups"] != "" {
			gs = strings.Split(v["groups"], ",")
		}
		code, _, err := s.h.Auth.CreateInvite(ctx, s.userID, auth.InviteOptions{
			MaxUses: uses, TTL: time.Duration(days) * 24 * time.Hour,
			RequireApproval: v["approval"] == form.True, Groups: gs, Note: v["note"],
		})
		if errors.Is(err, perm.ErrForbidden) && len(gs) > 0 {
			errs = form.Errors{"groups": errors.New("you cannot invite into a group with permissions you do not have")}
			continue
		}
		if err != nil {
			return err
		}
		return tui.Message(ctx, s.ui, s.title("Invite created"),
			"Invite code:",
			"",
			"    "+code,
			"",
			"Share it privately. It is shown only once and cannot be recovered.",
			fmt.Sprintf("To register, the new member connects with SSH as user %q and enters the code as the password.", s.h.Auth.InviteUser()),
		)
	}
}

func (s *session) manageInvites(ctx context.Context) error {
	invs, err := s.h.Auth.Invites(ctx, s.userID)
	if err != nil {
		return err
	}
	now := time.Now()
	p := tui.Page{Title: s.title("Invites")}
	var items []tui.MenuItem
	for _, inv := range invs {
		state := "usable"
		switch {
		case inv.RevokedAt != nil:
			state = "revoked"
		case inv.Uses >= inv.MaxUses:
			state = "used up"
		case inv.ExpiresAt != nil && !now.Before(*inv.ExpiresAt):
			state = "expired"
		}
		desc := fmt.Sprintf("Invite %d: %s, used %d of %d, expires %s", inv.ID, state, inv.Uses, inv.MaxUses, fmtTime(inv.ExpiresAt))
		if inv.Note != "" {
			desc += ", note: " + inv.Note
		}
		p.Lines = append(p.Lines, tui.Text(desc))
		if state == "usable" {
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(inv.ID, 10), Label: desc})
		}
	}
	if len(invs) == 0 {
		p.Lines = append(p.Lines, tui.Text("There are no invites."))
	}
	if err := s.ui.Show(ctx, p); err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}
	choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.title("Revoke an invite"), Intro: "Choose an invite to revoke, or go back.", Items: items})
	if err != nil {
		return err
	}
	ok, err := tui.Confirm(ctx, s.ui, s.title("Revoke an invite"), "Revoke this invite? It can no longer be used.")
	if err != nil || !ok {
		return err
	}
	id, _ := strconv.ParseInt(choice, 10, 64)
	if err := s.h.Auth.RevokeInvite(ctx, s.userID, id); err != nil {
		return err
	}
	return tui.Message(ctx, s.ui, s.title("Revoke an invite"), "Invite revoked.")
}

func (s *session) branding(ctx context.Context) error {
	fm := &form.Form{
		Title: "Branding",
		Fields: []form.Field{{
			Name: "name", Label: "BBS name", Kind: form.SingleLine, Required: true, MaxLen: settings.MaxBBSNameLen,
			Help:  "Shown in every title bar and on the welcome prompt.",
			Check: settings.NormalizeBBSName,
		}},
	}
	v, err := s.form(ctx, fm, form.Values{"name": s.name}, nil)
	if err != nil {
		return err
	}
	if err := s.h.Settings.SetBBSName(ctx, s.userID, v["name"]); err != nil {
		return err
	}
	s.name = s.h.Settings.BBSName(ctx)
	return tui.Message(ctx, s.ui, s.title("Branding"), "The BBS name has been changed. Other members see it the next time they connect.")
}
