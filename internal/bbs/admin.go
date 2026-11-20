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

// admin is the administration menu. Each section appears only to members
// holding a permission it needs; the services re-check every action.
func (s *session) admin(ctx context.Context) error {
	for {
		set, err := s.h.Perms.Permissions(ctx, s.userID)
		if err != nil {
			return err
		}
		var items []tui.MenuItem
		addIf := func(ok bool, value, label, help string) {
			if ok {
				items = append(items, tui.MenuItem{Value: value, Label: label, Help: help})
			}
		}
		addIf(set.Has(perm.UsersApprove), "pending", "Accounts awaiting approval", "Approve or reject new accounts")
		addIf(set.Has(perm.UsersManage) || set.Has(perm.GroupsManage), "users", "Users", "Find a user, lock or unlock, change groups")
		addIf(set.Has(perm.SessionsManage) && s.h.Sessions != nil, "online", "Who is online", "See SSH connections and end one")
		addIf(set.Has(perm.GroupsManage), "groups", "Groups and permissions", "Create groups, grant permissions, manage members")
		addIf(set.Has(perm.InviteCreate), "invite", "Create an invite", "")
		addIf(set.Has(perm.InviteCreate) || set.Has(perm.InviteManage), "invites", "View or revoke invites", "")
		addIf(set.Has(perm.SettingsManage), "branding", "Branding", "The BBS name shown in every title")
		addIf(set.Has(perm.SettingsManage), "limits", "Connection limits", "Idle timeout and connections per account")
		addIf(set.Has(perm.PluginSettings), "plugins", "Plugin settings", "Settings of installed plugins")
		addIf(set.Has(perm.MenuManage), "menu", "Menu editor", "Arrange the member menu")
		addIf(set.Has(perm.TransitionsManage) && s.h.Transitions != nil, "transitions", "Transitions", "Text art shown between the menu and applications")
		addIf(set.Has(perm.AuditView), "audit", "Audit log", "Recent administrative actions")

		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Administration"), Items: items})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "pending":
			err = s.pendingAccounts(ctx)
		case "users":
			err = s.adminUsers(ctx)
		case "online":
			err = s.whoIsOnline(ctx)
		case "groups":
			err = s.adminGroups(ctx)
		case "invite":
			err = s.createInvite(ctx)
		case "invites":
			err = s.manageInvites(ctx)
		case "branding":
			err = s.branding(ctx)
		case "limits":
			err = s.connectionLimits(ctx)
		case "plugins":
			err = s.pluginSettings(ctx)
		case "menu":
			err = s.menuEditor(ctx, 0, "Main menu")
		case "audit":
			err = s.auditLog(ctx)
		case "transitions":
			err = s.adminTransitions(ctx)
		}
		if msg := adminErrorMessage(err); msg != "" {
			err = tui.Message(ctx, s.ui, s.Title("Administration"), msg)
		}
		if err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

// adminErrorMessage turns expected service errors into a message for the
// administrator; "" means the error is not one of them.
func adminErrorMessage(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, perm.ErrForbidden):
		return "You do not have permission to do that. You can only change groups whose permissions you all hold, and only add or remove members of groups you are in yourself, and never someone holding permissions you lack."
	case errors.Is(err, perm.ErrLastAdmin):
		return "That would leave the BBS without an active administrator, so it was not done."
	case errors.Is(err, perm.ErrProtected):
		return "Built-in groups cannot be changed that way."
	}
	return ""
}

func (s *session) pendingAccounts(ctx context.Context) error {
	for {
		users, err := s.h.Auth.PendingUsers(ctx, s.userID)
		if err != nil {
			return err
		}
		if len(users) == 0 {
			return tui.Message(ctx, s.ui, s.Title("Approvals"), "No accounts are waiting for approval.")
		}
		var items []tui.MenuItem
		for _, u := range users {
			items = append(items, tui.MenuItem{Value: strconv.FormatInt(u.ID, 10), Label: u.Username, Help: "Registered " + fmtTime(&u.CreatedAt)})
		}
		choice, err := s.ui.Choose(ctx, tui.Menu{
			Title: s.Title("Approvals"), Intro: fmt.Sprintf("%d account(s) waiting. Choose one to approve or reject.", len(users)), Items: items,
		})
		if err != nil {
			return err
		}
		id, _ := strconv.ParseInt(choice, 10, 64)
		action, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Approvals"), Items: []tui.MenuItem{
			{Value: "approve", Label: "Approve", Help: "The account can use the BBS"},
			{Value: "reject", Label: "Reject", Help: "The account and its keys are deleted"},
		}})
		if errors.Is(err, tui.ErrCancelled) {
			continue
		}
		if err != nil {
			return err
		}
		if action == "approve" {
			err = s.h.Auth.Approve(ctx, s.userID, id)
		} else {
			ok, cerr := tui.Confirm(ctx, s.ui, s.Title("Approvals"), "Reject and delete this account?")
			if cerr != nil || !ok {
				continue
			}
			err = s.h.Auth.Reject(ctx, s.userID, id)
		}
		switch {
		case errors.Is(err, perm.ErrForbidden):
			err = tui.Message(ctx, s.ui, s.Title("Approvals"), "You cannot act on this account: it would receive permissions you do not have.")
		case errors.Is(err, auth.ErrNotPending):
			err = tui.Message(ctx, s.ui, s.Title("Approvals"), "This account is no longer pending.")
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
				Help: "Groups new accounts join. None selected means member. You can only choose groups whose permissions you have, and apart from member, only groups you are in yourself."},
			{Name: "note", Label: "Note for administrators", Kind: form.SingleLine, MaxLen: 200, Help: "Optional, e.g. who it is for. Never shown to the invitee."},
		},
	}
	vals := form.Values{"uses": "1", "days": "7", "approval": form.False}
	var errs form.Errors
	for {
		v, err := s.Form(ctx, fm, vals, errs)
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
			errs = form.Errors{"groups": errors.New("you cannot invite into a group you are not in, or one with permissions you do not have")}
			continue
		}
		if err != nil {
			return err
		}
		return tui.Message(ctx, s.ui, s.Title("Invite created"),
			"Invite code:",
			"",
			"    "+code,
			"",
			"Share it privately. It is shown only once and cannot be recovered.",
			fmt.Sprintf("To register, the new member connects with SSH as user %q and enters the code as the password.", s.h.Auth.InviteUser()),
		)
	}
}

// manageInvites lists invites as a menu, each with its state, uses left
// and note. Choosing one shows all its details, where a usable invite can
// be revoked.
func (s *session) manageInvites(ctx context.Context) error {
	for {
		invs, err := s.h.Auth.Invites(ctx, s.userID)
		if err != nil {
			return err
		}
		if len(invs) == 0 {
			return tui.Message(ctx, s.ui, s.Title("Invites"), "There are no invites.")
		}
		now := time.Now()
		byID := map[string]auth.Invite{}
		var items []tui.MenuItem
		usable := 0
		for _, inv := range invs {
			if inviteState(inv, now) == "usable" {
				usable++
			}
			id := strconv.FormatInt(inv.ID, 10)
			byID[id] = inv
			items = append(items, tui.MenuItem{Value: id, Label: inviteLabel(inv, now), Help: "Expires " + fmtTime(inv.ExpiresAt)})
		}
		intro := fmt.Sprintf("%d invite(s), %d usable. Choose one to see its details or revoke it.", len(invs), usable)
		choice, err := s.ui.Choose(ctx, tui.Menu{Title: s.Title("Invites"), Intro: intro, Items: items})
		if errors.Is(err, tui.ErrCancelled) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := s.inviteDetail(ctx, byID[choice]); err != nil && !errors.Is(err, tui.ErrCancelled) {
			return err
		}
	}
}

// inviteLabel is an invite's line in the list: its state, the uses left
// while it is usable, and the administrator's note.
func inviteLabel(inv auth.Invite, now time.Time) string {
	state := inviteState(inv, now)
	label := fmt.Sprintf("Invite %d: %s", inv.ID, state)
	if state == "usable" {
		label += fmt.Sprintf(", %d of %d uses left", inv.MaxUses-inv.Uses, inv.MaxUses)
	}
	if inv.Note != "" {
		label += ", note: " + inv.Note
	}
	return label
}

// inviteDetail shows everything about an invite. A usable invite can be
// revoked from here, after a confirmation.
func (s *session) inviteDetail(ctx context.Context, inv auth.Invite) error {
	now := time.Now()
	state := inviteState(inv, now)
	title := s.Title(fmt.Sprintf("Invite %d", inv.ID))
	approval := "no"
	if inv.RequireApproval {
		approval = "yes"
	}
	note := inv.Note
	if note == "" {
		note = "none"
	}
	lines := []string{
		"State: " + state + ".",
		fmt.Sprintf("Uses: %d of %d used, %d left.", inv.Uses, inv.MaxUses, max(0, inv.MaxUses-inv.Uses)),
		"Created: " + fmtTime(&inv.CreatedAt) + ".",
		"Expires: " + fmtTime(inv.ExpiresAt) + ".",
	}
	if inv.RevokedAt != nil {
		lines = append(lines, "Revoked: "+fmtTime(inv.RevokedAt)+".")
	}
	lines = append(lines, "New accounts need approval: "+approval+".", "Note: "+note)
	if state != "usable" {
		return tui.Message(ctx, s.ui, title, append(lines, "", "This invite can no longer be used, so there is nothing to revoke.")...)
	}
	choice, err := s.ui.Choose(ctx, tui.Menu{Title: title, Intro: strings.Join(lines, " "),
		Items: []tui.MenuItem{{Value: "revoke", Label: "Revoke this invite", Help: "It can no longer be used to register"}}})
	if err != nil || choice != "revoke" {
		return err
	}
	ok, err := tui.Confirm(ctx, s.ui, title, fmt.Sprintf("Revoke invite %d? It can no longer be used.", inv.ID))
	if err != nil || !ok {
		return err
	}
	if err := s.h.Auth.RevokeInvite(ctx, s.userID, inv.ID); err != nil {
		return err
	}
	return tui.Message(ctx, s.ui, title, "Invite revoked.")
}

// inviteState describes whether an invite can still be used.
func inviteState(inv auth.Invite, now time.Time) string { return inv.State(now) }

func (s *session) branding(ctx context.Context) error {
	fm := &form.Form{
		Title: "Branding",
		Fields: []form.Field{{
			Name: "name", Label: "BBS name", Kind: form.SingleLine, Required: true, MaxLen: settings.MaxBBSNameLen,
			Help:  "Shown in every title bar and on the welcome prompt.",
			Check: settings.NormalizeBBSName,
		}},
	}
	v, err := s.Form(ctx, fm, form.Values{"name": s.name}, nil)
	if err != nil {
		return err
	}
	if err := s.h.Settings.SetBBSName(ctx, s.userID, v["name"]); err != nil {
		return err
	}
	s.name = s.h.Settings.BBSName(ctx)
	return tui.Message(ctx, s.ui, s.Title("Branding"), "The BBS name has been changed. Other members see it the next time they connect.")
}
