package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

const maxEmailLen = 254

// ErrEmailInvalid is returned for a malformed email address.
var ErrEmailInvalid = errors.New("email address is not valid")

// Registration is what the registration wizard collects.
type Registration struct {
	Username  string
	Password  string // used later for "add key" logins
	Email     string // optional
	PublicKey string // authorized_keys line
	KeyLabel  string // optional; defaults to the key comment
}

// NormalizeEmail validates an optional email address. Display names
// ("Name <a@b>") are refused so exactly an address is stored.
func NormalizeEmail(e string) (string, error) {
	e = strings.TrimSpace(e)
	if e == "" {
		return "", nil
	}
	if len(e) > maxEmailLen {
		return "", ErrEmailInvalid
	}
	addr, err := mail.ParseAddress(e)
	if err != nil || addr.Name != "" || addr.Address != e {
		return "", ErrEmailInvalid
	}
	return e, nil
}

// Register creates an account using an invite code. Everything happens in
// one transaction: the invite is re-checked and a use consumed, the account
// and its first key are created, and the invite's groups assigned. The
// account is active immediately unless the invite requires approval.
func (s *Service) Register(ctx context.Context, inviteCode string, r Registration) (User, error) {
	username := NormalizeUsername(r.Username)
	if err := ValidateUsername(username, s.inviteUser); err != nil {
		return User{}, err
	}
	if err := ValidatePassword(r.Password); err != nil {
		return User{}, err
	}
	email, err := NormalizeEmail(r.Email)
	if err != nil {
		return User{}, err
	}
	key, comment, err := ParsePublicKey(r.PublicKey)
	if err != nil {
		return User{}, err
	}
	label := r.KeyLabel
	if strings.TrimSpace(label) == "" {
		label = comment
	}
	// Hash before the transaction: it is slow and needs no lock.
	hash, err := HashPassword(ctx, r.Password)
	if err != nil {
		return User{}, err
	}

	var userID int64
	var status string
	err = store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		now := s.now()
		inv, err := checkInvite(ctx, tx, inviteCode, now)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE invites SET uses = uses + 1 WHERE id = ? AND uses < max_uses AND revoked_at IS NULL`, inv.ID)
		if err != nil {
			return fmt.Errorf("auth: consume invite: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrInviteInvalid
		}

		status = StatusActive
		var approvedAt any = store.FormatTime(now)
		if inv.RequireApproval {
			status, approvedAt = StatusPending, nil
		}
		var emailArg any
		if email != "" {
			emailArg = email
		}
		res, err = tx.ExecContext(ctx, `
			INSERT INTO users (id, username, password_hash, email, status, created_at, approved_at, invite_id)
			VALUES ((SELECT high + 1 FROM user_id_high), ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (username) DO NOTHING`,
			username, hash, emailArg, status, store.FormatTime(now), approvedAt, inv.ID)
		if err != nil {
			return fmt.Errorf("auth: create user: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrUsernameTaken
		}
		userID, _ = res.LastInsertId()

		if _, err := addKey(ctx, tx, now, userID, key, label); err != nil {
			return err
		}
		if err := assignInviteGroups(ctx, tx, userID, inv.ID); err != nil {
			return err
		}
		return audit.Record(ctx, tx, now, audit.Entry{
			Actor: userID, Action: audit.UserRegistered, TargetType: "invite", TargetID: inv.ID, Detail: status,
		})
	})
	if err != nil {
		s.log.Info("registration failed", "reason", err)
		return User{}, err
	}
	s.log.Info("account registered", "user_id", userID, "status", status)
	s.publish(ctx, events.UserRegistered, userID, userID)
	return s.UserByID(ctx, userID)
}

func assignInviteGroups(ctx context.Context, tx *sql.Tx, userID, inviteID int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT group_id FROM invite_groups WHERE invite_id = ?`, inviteID)
	if err != nil {
		return fmt.Errorf("auth: invite groups: %w", err)
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(ids) == 0 {
		// The invite's groups were deleted after it was issued: fall back
		// to the default group rather than creating a group-less account.
		var id int64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM access_groups WHERE name = ?`, perm.GroupMember).Scan(&id); err != nil {
			return fmt.Errorf("auth: member group: %w", err)
		}
		ids = []int64{id}
	}
	for _, id := range ids {
		if err := perm.AddMemberSystem(ctx, tx, userID, id); err != nil {
			return err
		}
	}
	return nil
}
