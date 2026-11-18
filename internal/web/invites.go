package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Invites: create (core.invite.create), list and revoke (your own, or all
// with core.invite.manage). The auth service checks the permissions,
// including that an invite only grants groups whose permissions the
// creator holds. A new code is shown once, in the response to the form;
// it is never put in a URL or stored.

const errInviteForbidden = "You do not have permission to manage invites."

var inviteNotices = map[string]string{
	"revoked": "The invite has been revoked.",
	"gone":    "That invite has already been revoked.",
}

type inviteRow struct {
	ID                            int64
	State, Expires, Creator, Note string
	Uses, MaxUses                 int
	Usable, Approval              bool
}

// inviter returns the session of a member who may see invites, and the
// member's permissions.
func (s *Server) inviter(w http.ResponseWriter, r *http.Request) (*websess.Session, perm.Set) {
	sess := sessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil, nil
	}
	set, err := s.cfg.Perms.Permissions(r.Context(), sess.UserID)
	if err != nil || (!set.Has(perm.InviteCreate) && !set.Has(perm.InviteManage)) {
		s.renderError(w, r, http.StatusForbidden, errInviteForbidden)
		return nil, nil
	}
	return sess, set
}

func fmtExpiry(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return fmtSince(*t)
}

func inviteState(inv auth.Invite, now time.Time) string {
	switch {
	case inv.RevokedAt != nil:
		return "revoked"
	case inv.Uses >= inv.MaxUses:
		return "used up"
	case inv.ExpiresAt != nil && !now.Before(*inv.ExpiresAt):
		return "expired"
	}
	return "usable"
}

func (s *Server) handleInvites(w http.ResponseWriter, r *http.Request) {
	sess, set := s.inviter(w, r)
	if sess == nil {
		return
	}
	invs, err := s.cfg.Auth.Invites(r.Context(), sess.UserID)
	if err != nil {
		s.inviteFailure(w, r, err)
		return
	}
	now := time.Now()
	names := map[int64]string{}
	rows := make([]inviteRow, 0, len(invs))
	for _, inv := range invs {
		row := inviteRow{ID: inv.ID, State: inviteState(inv, now), Expires: fmtExpiry(inv.ExpiresAt), Note: inv.Note,
			Uses: inv.Uses, MaxUses: inv.MaxUses, Usable: inv.Usable(now), Approval: inv.RequireApproval}
		switch name, ok := names[inv.CreatedBy]; {
		case inv.CreatedBy == 0:
			row.Creator = "operator"
		case ok:
			row.Creator = name
		default:
			row.Creator = "deleted account"
			if u, err := s.cfg.Auth.UserByID(r.Context(), inv.CreatedBy); err == nil {
				row.Creator = u.Username
			}
			names[inv.CreatedBy] = row.Creator
		}
		rows = append(rows, row)
	}
	s.render(w, r, http.StatusOK, "Invites", "invites", map[string]any{
		"Rows": rows, "All": set.Has(perm.InviteManage), "CanCreate": set.Has(perm.InviteCreate),
		"Notice": inviteNotices[r.URL.Query().Get("done")],
	})
}

// inviteForm is the create form, the same as over SSH.
func (s *Server) inviteForm(r *http.Request) (*form.Form, error) {
	groups, err := s.cfg.Perms.Groups(r.Context())
	if err != nil {
		return nil, err
	}
	var opts []form.Option
	for _, g := range groups {
		opts = append(opts, form.Option{Value: g.Name, Label: g.Name})
	}
	return &form.Form{Fields: []form.Field{
		{Name: "uses", Label: "Number of accounts it can create", Kind: form.SingleLine, Subtype: form.Int, Required: true,
			Min: form.Bound(1), Max: form.Bound(auth.MaxInviteUses)},
		{Name: "days", Label: "Days until it expires", Kind: form.SingleLine, Subtype: form.Int, Required: true,
			Min: form.Bound(1), Max: form.Bound(auth.MaxInviteTTL.Hours() / 24)},
		{Name: "approval", Label: "New accounts need approval", Kind: form.Boolean},
		{Name: "groups", Label: "Groups", Kind: form.Choice, Multi: true, Options: opts,
			Help: "Groups new accounts join. None selected means member. You can only choose groups whose permissions you have."},
		{Name: "note", Label: "Note for administrators", Kind: form.SingleLine, MaxLen: 200, Help: "Optional, e.g. who it is for. Never shown to the invitee."},
	}}, nil
}

func (s *Server) renderInviteForm(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, fm *form.Form, vals form.Values, errs form.Errors, msg string) {
	s.render(w, r, status, "Create an invite", "invite-new", map[string]any{
		"CSRF": sess.CSRF, "Fields": fieldViews(fm, vals, errs), "Error": msg,
	})
}

func (s *Server) creator(w http.ResponseWriter, r *http.Request) *websess.Session {
	return s.requirePerm(w, r, perm.InviteCreate, "You do not have permission to create invites.")
}

func (s *Server) handleInviteNew(w http.ResponseWriter, r *http.Request) {
	sess := s.creator(w, r)
	if sess == nil {
		return
	}
	fm, err := s.inviteForm(r)
	if err != nil {
		s.inviteFailure(w, r, err)
		return
	}
	s.renderInviteForm(w, r, http.StatusOK, sess, fm, form.Values{"uses": "1", "days": "7", "approval": form.False}, nil, "")
}

func (s *Server) handleInviteCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess := s.creator(w, r)
	if sess == nil {
		return
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return
	}
	fm, err := s.inviteForm(r)
	if err != nil {
		s.inviteFailure(w, r, err)
		return
	}
	raw := formValues(fm, r)
	vals, errs := fm.Validate(raw)
	if len(errs) > 0 {
		s.renderInviteForm(w, r, http.StatusUnprocessableEntity, sess, fm, raw, errs, "The invite was not created. Correct the fields marked below.")
		return
	}
	uses, _ := strconv.Atoi(vals["uses"])
	days, _ := strconv.Atoi(vals["days"])
	var groups []string
	if vals["groups"] != "" {
		groups = strings.Split(vals["groups"], ",")
	}
	code, inv, err := s.cfg.Auth.CreateInvite(r.Context(), sess.UserID, auth.InviteOptions{
		MaxUses: uses, TTL: time.Duration(days) * 24 * time.Hour,
		RequireApproval: vals["approval"] == form.True, Groups: groups, Note: vals["note"],
	})
	switch {
	case errors.Is(err, perm.ErrForbidden) && len(groups) > 0:
		s.renderInviteForm(w, r, http.StatusForbidden, sess, fm, raw,
			form.Errors{"groups": errors.New("cannot include a group with permissions you do not have")}, "The invite was not created.")
		return
	case err != nil:
		s.inviteFailure(w, r, err)
		return
	}
	LoggerFrom(r.Context()).Info("invite created from the web", "actor", sess.UserID, "invite_id", inv.ID)
	// Rendered, not redirected: the code must not appear in a URL.
	s.render(w, r, http.StatusOK, "Invite created", "invite-created", map[string]any{
		"ID": inv.ID, "Code": code, "SSHAddress": s.cfg.SSHAddress, "InviteUser": s.cfg.InviteUser,
		"MaxUses": inv.MaxUses, "Expires": fmtExpiry(inv.ExpiresAt), "Approval": inv.RequireApproval,
	})
}

// revocable finds a usable invite the member may see.
func (s *Server) revocable(r *http.Request, actor int64) (auth.Invite, bool, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return auth.Invite{}, false, nil
	}
	invs, err := s.cfg.Auth.Invites(r.Context(), actor)
	if err != nil {
		return auth.Invite{}, false, err
	}
	for _, inv := range invs {
		if inv.ID == id && inv.RevokedAt == nil {
			return inv, true, nil
		}
	}
	return auth.Invite{}, false, nil
}

func (s *Server) renderRevoke(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, inv auth.Invite, msg string) {
	s.render(w, r, status, "Revoke an invite", "invite-revoke", map[string]any{
		"ID": inv.ID, "Uses": inv.Uses, "MaxUses": inv.MaxUses, "Expires": fmtExpiry(inv.ExpiresAt), "Note": inv.Note,
		"CSRF": sess.CSRF, "Error": msg,
	})
}

func (s *Server) handleInviteRevokeConfirm(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.inviter(w, r)
	if sess == nil {
		return
	}
	inv, ok, err := s.revocable(r, sess.UserID)
	switch {
	case err != nil:
		s.inviteFailure(w, r, err)
	case !ok:
		http.Redirect(w, r, "/admin/invites?done=gone", http.StatusSeeOther)
	default:
		s.renderRevoke(w, r, http.StatusOK, sess, inv, "")
	}
}

func (s *Server) handleInviteRevoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	sess, _ := s.inviter(w, r)
	if sess == nil {
		return
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return
	}
	inv, ok, err := s.revocable(r, sess.UserID)
	switch {
	case err != nil:
		s.inviteFailure(w, r, err)
		return
	case !ok:
		http.Redirect(w, r, "/admin/invites?done=gone", http.StatusSeeOther)
		return
	case r.PostForm.Get("confirm") != "yes":
		s.renderRevoke(w, r, http.StatusUnprocessableEntity, sess, inv, "Tick the box to confirm, then try again.")
		return
	}
	switch err := s.cfg.Auth.RevokeInvite(r.Context(), sess.UserID, inv.ID); {
	case errors.Is(err, auth.ErrNotFound):
		http.Redirect(w, r, "/admin/invites?done=gone", http.StatusSeeOther)
	case err != nil:
		s.inviteFailure(w, r, err)
	default:
		LoggerFrom(r.Context()).Info("invite revoked from the web", "actor", sess.UserID, "invite_id", inv.ID)
		http.Redirect(w, r, "/admin/invites?done=revoked", http.StatusSeeOther)
	}
}

func (s *Server) inviteFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, perm.ErrForbidden):
		s.renderError(w, r, http.StatusForbidden, errInviteForbidden)
	case errors.Is(err, auth.ErrInviteOptions):
		s.renderError(w, r, http.StatusBadRequest, "Those invite options are not allowed.")
	default:
		LoggerFrom(r.Context()).Error("invites", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
	}
}
