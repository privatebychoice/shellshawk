package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// Invite limits.
const (
	DefaultInviteTTL  = 7 * 24 * time.Hour
	MaxInviteTTL      = 90 * 24 * time.Hour
	MaxInviteUses     = 100
	BootstrapTTL      = 24 * time.Hour
	inviteCodeBytes   = 16 // 128 bits
	maxInviteNoteLen  = 200
	inviteCodeGroupSz = 5
	bootstrapNote     = "bootstrap administrator"
)

// Invite errors.
var (
	ErrInviteInvalid = errors.New("invite code is invalid, expired, used up or revoked")
	ErrInviteOptions = errors.New("invalid invite options")
	ErrBootstrapDone = errors.New("an administrator already exists; use an admin account to create invites")
)

// crockford is Crockford's base32 alphabet: no I, L, O or U, so codes are
// unambiguous when read aloud or typed.
var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// NormalizeInviteCode uppercases, drops separators and maps the characters
// Crockford base32 treats as aliases (O→0, I/L→1).
func NormalizeInviteCode(code string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(code) {
		switch {
		case r == '-' || r == ' ' || r == '\t':
		case r == 'O':
			b.WriteRune('0')
		case r == 'I' || r == 'L':
			b.WriteRune('1')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hashInviteCode(code string) string {
	sum := sha256.Sum256([]byte(NormalizeInviteCode(code)))
	return hex.EncodeToString(sum[:])
}

// newInviteCode returns a random code formatted in dash-separated groups.
func newInviteCode() (string, error) {
	b := make([]byte, inviteCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	raw := crockford.EncodeToString(b)
	var parts []string
	for len(raw) > inviteCodeGroupSz+1 {
		parts = append(parts, raw[:inviteCodeGroupSz])
		raw = raw[inviteCodeGroupSz:]
	}
	parts = append(parts, raw)
	return strings.Join(parts, "-"), nil
}

// InviteOptions configures a new invite. Zero values take defaults:
// 1 use, DefaultInviteTTL, no approval required, the "member" group.
type InviteOptions struct {
	MaxUses         int
	TTL             time.Duration
	RequireApproval bool
	Groups          []string // group names granted on registration
	Note            string   // shown to admins only
}

// Invite is an invite's metadata. The code itself is never stored.
type Invite struct {
	ID              int64
	CreatedBy       int64 // 0 = system/operator
	CreatedAt       time.Time
	ExpiresAt       *time.Time
	MaxUses         int
	Uses            int
	RequireApproval bool
	Note            string
	RevokedAt       *time.Time
}

// Usable reports whether the invite can still register an account at now.
func (i Invite) Usable(now time.Time) bool {
	return i.RevokedAt == nil && i.Uses < i.MaxUses && (i.ExpiresAt == nil || now.Before(*i.ExpiresAt))
}

// CreateInvite creates an invite and returns its code, which is shown once
// and cannot be recovered. Attaching groups requires the actor to hold every
// permission those groups grant.
func (s *Service) CreateInvite(ctx context.Context, actor int64, opt InviteOptions) (string, Invite, error) {
	if opt.MaxUses == 0 {
		opt.MaxUses = 1
	}
	if opt.TTL == 0 {
		opt.TTL = DefaultInviteTTL
	}
	opt.Note = cleanLabel(opt.Note)
	if r := []rune(opt.Note); len(r) > maxInviteNoteLen {
		opt.Note = string(r[:maxInviteNoteLen])
	}
	if opt.MaxUses < 1 || opt.MaxUses > MaxInviteUses || opt.TTL < 0 || opt.TTL > MaxInviteTTL {
		return "", Invite{}, ErrInviteOptions
	}

	var code string
	var id int64
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		actorPerms, err := s.perms.Permissions(ctx, actor)
		if err != nil {
			return err
		}
		if !actorPerms.Has(perm.InviteCreate) {
			return perm.ErrForbidden
		}
		groupIDs, err := s.resolveInviteGroups(ctx, opt.Groups, actorPerms)
		if err != nil {
			return err
		}
		code, id, err = s.insertInvite(ctx, tx, actor, opt, groupIDs)
		return err
	})
	if err != nil {
		return "", Invite{}, err
	}
	s.log.Info("invite created", "actor", actor, "invite_id", id, "max_uses", opt.MaxUses, "require_approval", opt.RequireApproval)
	inv, err := s.inviteByID(ctx, id)
	return code, inv, err
}

func (s *Service) resolveInviteGroups(ctx context.Context, names []string, actorPerms perm.Set) ([]int64, error) {
	if len(names) == 0 {
		names = []string{perm.GroupMember}
	}
	var ids []int64
	for _, n := range names {
		g, err := s.perms.GroupByName(ctx, n)
		if err != nil {
			return nil, err
		}
		for _, p := range g.Permissions {
			if !actorPerms.Has(p) {
				return nil, fmt.Errorf("%w: group %q grants %s", perm.ErrForbidden, g.Name, p)
			}
		}
		ids = append(ids, g.ID)
	}
	return ids, nil
}

func (s *Service) insertInvite(ctx context.Context, tx *sql.Tx, actor int64, opt InviteOptions, groupIDs []int64) (string, int64, error) {
	code, err := newInviteCode()
	if err != nil {
		return "", 0, err
	}
	now := s.now()
	var createdBy any
	if actor != audit.SystemActor {
		createdBy = actor
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO invites (code_hash, created_by, created_at, expires_at, max_uses, require_approval, note)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hashInviteCode(code), createdBy, store.FormatTime(now), store.FormatTime(now.Add(opt.TTL)),
		opt.MaxUses, opt.RequireApproval, opt.Note)
	if err != nil {
		return "", 0, fmt.Errorf("auth: create invite: %w", err)
	}
	id, _ := res.LastInsertId()
	for _, gid := range groupIDs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO invite_groups (invite_id, group_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, id, gid); err != nil {
			return "", 0, fmt.Errorf("auth: invite group: %w", err)
		}
	}
	if err := audit.Record(ctx, tx, now, audit.Entry{Actor: actor, Action: audit.InviteCreated, TargetType: "invite", TargetID: id}); err != nil {
		return "", 0, err
	}
	return code, id, nil
}

// CreateBootstrapInvite creates a single-use, 24-hour invite into the admin
// group with no approval step. It only works while there is no active
// administrator, so it cannot be used to gain admin on a running system.
// Any earlier unused bootstrap invite is revoked, so at most one is ever
// valid. It is for the operator CLI, not for SSH or web users.
func (s *Service) CreateBootstrapInvite(ctx context.Context) (string, error) {
	var code string
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		n, err := perm.CountActiveAdmins(ctx, tx)
		if err != nil {
			return err
		}
		if n > 0 {
			return ErrBootstrapDone
		}
		g, err := s.perms.GroupByName(ctx, perm.GroupAdmin)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE invites SET revoked_at = ?
			WHERE created_by IS NULL AND note = ? AND revoked_at IS NULL AND uses = 0`,
			store.FormatTime(s.now()), bootstrapNote)
		if err != nil {
			return fmt.Errorf("auth: revoke old bootstrap invites: %w", err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			s.log.Info("previous bootstrap invite revoked", "count", n)
		}
		code, _, err = s.insertInvite(ctx, tx, audit.SystemActor,
			InviteOptions{MaxUses: 1, TTL: BootstrapTTL, Note: bootstrapNote}, []int64{g.ID})
		return err
	})
	if err == nil {
		s.log.Warn("bootstrap admin invite created", "ttl", BootstrapTTL)
	}
	return code, err
}

const inviteColumns = `id, COALESCE(created_by, 0), created_at, expires_at, max_uses, uses, require_approval, note, revoked_at`

func scanInvite(row interface{ Scan(...any) error }) (Invite, error) {
	var inv Invite
	var created string
	var expires, revoked sql.NullString
	if err := row.Scan(&inv.ID, &inv.CreatedBy, &created, &expires, &inv.MaxUses, &inv.Uses, &inv.RequireApproval, &inv.Note, &revoked); err != nil {
		return Invite{}, err
	}
	var err error
	if inv.CreatedAt, err = store.ParseTime(created); err != nil {
		return Invite{}, err
	}
	if inv.ExpiresAt, err = store.ScanNullTime(expires); err != nil {
		return Invite{}, err
	}
	inv.RevokedAt, err = store.ScanNullTime(revoked)
	return inv, err
}

func (s *Service) inviteByID(ctx context.Context, id int64) (Invite, error) {
	inv, err := scanInvite(s.db.QueryRowContext(ctx, `SELECT `+inviteColumns+` FROM invites WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, ErrNotFound
	}
	return inv, err
}

// CheckInvite returns the invite for code if it is usable. It does not
// consume a use; Register does that.
func (s *Service) CheckInvite(ctx context.Context, code string) (Invite, error) {
	return checkInvite(ctx, s.db, code, s.now())
}

func checkInvite(ctx context.Context, db store.DBTX, code string, now time.Time) (Invite, error) {
	norm := NormalizeInviteCode(code)
	if norm == "" || len(norm) > 64 {
		return Invite{}, ErrInviteInvalid
	}
	inv, err := scanInvite(db.QueryRowContext(ctx, `SELECT `+inviteColumns+` FROM invites WHERE code_hash = ?`, hashInviteCode(norm)))
	if errors.Is(err, sql.ErrNoRows) {
		return Invite{}, ErrInviteInvalid
	}
	if err != nil {
		return Invite{}, fmt.Errorf("auth: check invite: %w", err)
	}
	if !inv.Usable(now) {
		return Invite{}, ErrInviteInvalid
	}
	return inv, nil
}

// Invites lists invites, newest first: all of them for holders of
// core.invite.manage, otherwise only the actor's own.
func (s *Service) Invites(ctx context.Context, actor int64) ([]Invite, error) {
	set, err := s.perms.Permissions(ctx, actor)
	if err != nil {
		return nil, err
	}
	var rows *sql.Rows
	switch {
	case set.Has(perm.InviteManage):
		rows, err = s.db.QueryContext(ctx, `SELECT `+inviteColumns+` FROM invites ORDER BY created_at DESC, id DESC`)
	case set.Has(perm.InviteCreate):
		rows, err = s.db.QueryContext(ctx, `SELECT `+inviteColumns+` FROM invites WHERE created_by = ? ORDER BY created_at DESC, id DESC`, actor)
	default:
		return nil, perm.ErrForbidden
	}
	if err != nil {
		return nil, fmt.Errorf("auth: list invites: %w", err)
	}
	defer rows.Close()
	var out []Invite
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// RevokeInvite revokes an invite: the actor's own, or any with
// core.invite.manage.
func (s *Service) RevokeInvite(ctx context.Context, actor, inviteID int64) error {
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		set, err := s.perms.Permissions(ctx, actor)
		if err != nil {
			return err
		}
		var owner sql.NullInt64
		err = tx.QueryRowContext(ctx, `SELECT created_by FROM invites WHERE id = ? AND revoked_at IS NULL`, inviteID).Scan(&owner)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("auth: revoke invite: %w", err)
		}
		own := owner.Valid && owner.Int64 == actor && set.Has(perm.InviteCreate)
		if !own && !set.Has(perm.InviteManage) {
			return perm.ErrForbidden
		}
		now := s.now()
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET revoked_at = ? WHERE id = ?`, store.FormatTime(now), inviteID); err != nil {
			return fmt.Errorf("auth: revoke invite: %w", err)
		}
		s.log.Info("invite revoked", "actor", actor, "invite_id", inviteID)
		return audit.Record(ctx, tx, now, audit.Entry{Actor: actor, Action: audit.InviteRevoked, TargetType: "invite", TargetID: inviteID})
	})
}
