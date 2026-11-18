// Package audit records security-relevant actions (approvals, invites, group
// and key changes) in the audit_log table.
//
// Entries must not contain secrets, passwords, invite codes or personal data
// beyond account IDs.
package audit

import (
	"context"
	"database/sql"
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
	MenuChanged        = "menu.changed"
	AdminViewedEmail   = "admin.viewed.email"
	ErasureRequested   = "user.erasure.requested"
	ErasureCancelled   = "user.erasure.cancelled"
	UserErased         = "user.erased"
	PluginSettingSet   = "plugin.setting.changed"
	ConnectionEnded    = "connection.ended"
	WebSessionEnded    = "web_session.ended"
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

// Listed is an audit entry as listed for administrators.
type Listed struct {
	At         time.Time
	Actor      string // username, "system", or "#<id>" if the account is gone
	Action     string
	TargetType string
	TargetID   string
	Detail     string
}

// Recent returns up to limit entries, newest first. Callers must check
// core.audit.view first (this package cannot import perm).
func Recent(ctx context.Context, db store.DBTX, limit int) ([]Listed, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT a.at, a.actor_id, COALESCE(u.username, ''), a.action, a.target_type, a.target_id, a.detail
		FROM audit_log a LEFT JOIN users u ON u.id = a.actor_id
		ORDER BY a.at DESC, a.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	defer rows.Close()
	var out []Listed
	for rows.Next() {
		var r Listed
		var at, name string
		var actor sql.NullInt64
		if err := rows.Scan(&at, &actor, &name, &r.Action, &r.TargetType, &r.TargetID, &r.Detail); err != nil {
			return nil, err
		}
		if r.At, err = store.ParseTime(at); err != nil {
			return nil, err
		}
		switch {
		case !actor.Valid:
			r.Actor = "system"
		case name != "":
			r.Actor = name
		default:
			r.Actor = "#" + strconv.FormatInt(actor.Int64, 10)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
