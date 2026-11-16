// Package audit records security-relevant actions (approvals, invites, group
// and key changes) in the audit_log table.
//
// Entries must not contain secrets, passwords, invite codes or personal data
// beyond account IDs.
package audit

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"go.privatebychoice.com/shellshawk/internal/store"
)

// Actions recorded by core. Plugins use their own "<plugin>." prefix.
const (
	UserRegistered     = "user.registered"
	UserApproved       = "user.approved"
	UserRejected       = "user.rejected"
	UserLocked         = "user.locked"
	UserUnlocked       = "user.unlocked"
	KeyAdded           = "key.added"
	KeyRemoved         = "key.removed"
	InviteCreated      = "invite.created"
	InviteRevoked      = "invite.revoked"
	GroupCreated       = "group.created"
	GroupDeleted       = "group.deleted"
	GroupGranted       = "group.permission.granted"
	GroupRevoked       = "group.permission.revoked"
	GroupMemberAdded   = "group.member.added"
	GroupMemberRemoved = "group.member.removed"
	SettingChanged     = "setting.changed"
)

// SystemActor marks an action taken by the system or operator CLI rather
// than a logged-in user.
const SystemActor int64 = 0

// Entry is one audit record.
type Entry struct {
	Actor      int64 // user ID, or SystemActor
	Action     string
	TargetType string // "user", "group", "invite", "key", …
	TargetID   int64
	Detail     string // short, non-sensitive context
}

// Record writes e using db, which may be a transaction so the audit row
// commits or rolls back together with the change it describes.
func Record(ctx context.Context, db store.DBTX, now time.Time, e Entry) error {
	var actor any
	if e.Actor != SystemActor {
		actor = e.Actor
	}
	target := ""
	if e.TargetID != 0 {
		target = strconv.FormatInt(e.TargetID, 10)
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO audit_log (at, actor_id, action, target_type, target_id, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		store.FormatTime(now), actor, e.Action, e.TargetType, target, e.Detail)
	if err != nil {
		return fmt.Errorf("audit: record %s: %w", e.Action, err)
	}
	return nil
}

// Purge deletes entries older than retention and returns how many were
// removed.
func Purge(ctx context.Context, db store.DBTX, now time.Time, retention time.Duration) (int64, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM audit_log WHERE at < ?`, store.FormatTime(now.Add(-retention)))
	if err != nil {
		return 0, fmt.Errorf("audit: purge: %w", err)
	}
	return res.RowsAffected()
}
