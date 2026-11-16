// Package auth manages accounts: users, SSH keys, invites, registration and
// approval, and implements sshd.Authenticator (docs/DESIGN.md §4, §6.1).
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// Account statuses.
const (
	StatusPending = "pending" // registered, awaiting approval
	StatusActive  = "active"
	StatusLocked  = "locked" // cannot log in
)

// Errors returned by Service.
var (
	ErrNotFound      = errors.New("not found")
	ErrUsernameTaken = errors.New("username is already taken")
	ErrNotPending    = errors.New("account is not pending approval")
	ErrSelf          = errors.New("cannot perform this action on your own account")
)

// User is an account. The password hash is never exposed.
type User struct {
	ID          int64
	Username    string
	Email       string
	Status      string
	CreatedAt   time.Time
	LastLoginAt *time.Time
}

// Publisher receives account events. *events.Bus implements it.
type Publisher interface {
	Publish(ctx context.Context, e events.Event) error
}

// Service manages accounts.
type Service struct {
	db         *sql.DB
	events     Publisher
	perms      *perm.Service
	inviteUser string
	now        func() time.Time
	log        *slog.Logger
}

// NewService returns a Service. inviteUser is the SSH login name used for
// invite registration (reserved as a username). now may be nil.
func NewService(db *sql.DB, perms *perm.Service, inviteUser string, now func() time.Time, log *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, perms: perms, inviteUser: NormalizeUsername(inviteUser), now: now, log: log.With("component", "auth")}
}

// SetPublisher makes the service publish account events after each change
// commits. Subscriber failures are logged by the bus and never undo the
// change.
func (s *Service) SetPublisher(p Publisher) { s.events = p }

func (s *Service) publish(ctx context.Context, topic string, userID, actor int64) {
	if s.events != nil {
		_ = s.events.Publish(ctx, events.Event{Topic: topic, UserID: userID, Actor: actor})
	}
}

// InviteUser returns the configured registration login name.
func (s *Service) InviteUser() string { return s.inviteUser }

const userColumns = `id, username, COALESCE(email, ''), status, created_at, last_login_at`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var created string
	var lastLogin sql.NullString
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Status, &created, &lastLogin); err != nil {
		return User{}, err
	}
	var err error
	if u.CreatedAt, err = store.ParseTime(created); err != nil {
		return User{}, fmt.Errorf("auth: user %d created_at: %w", u.ID, err)
	}
	if u.LastLoginAt, err = store.ScanNullTime(lastLogin); err != nil {
		return User{}, fmt.Errorf("auth: user %d last_login_at: %w", u.ID, err)
	}
	return u, nil
}

func userBy(ctx context.Context, db store.DBTX, where string, arg any) (User, error) {
	u, err := scanUser(db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE `+where, arg))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("auth: get user: %w", err)
	}
	return u, nil
}

// UserByID returns a user.
func (s *Service) UserByID(ctx context.Context, id int64) (User, error) {
	return userBy(ctx, s.db, "id = ?", id)
}

// UserByUsername returns a user (case-insensitive).
func (s *Service) UserByUsername(ctx context.Context, username string) (User, error) {
	return userBy(ctx, s.db, "username = ?", NormalizeUsername(username))
}

// RecordLogin stamps the user's last login and the key's last use. It is
// called only after the SSH handshake (including signature verification)
// has completed.
func (s *Service) RecordLogin(ctx context.Context, userID int64, keyFingerprint string) error {
	now := store.FormatTime(s.now())
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, now, userID); err != nil {
		return fmt.Errorf("auth: record login: %w", err)
	}
	if keyFingerprint != "" {
		if _, err := s.db.ExecContext(ctx, `UPDATE user_keys SET last_used_at = ? WHERE fingerprint = ? AND user_id = ?`, now, keyFingerprint, userID); err != nil {
			return fmt.Errorf("auth: record key use: %w", err)
		}
	}
	return nil
}

// ---- approvals and account status ---------------------------------------

// PendingUsers lists accounts awaiting approval, oldest first.
func (s *Service) PendingUsers(ctx context.Context, actor int64) ([]User, error) {
	if err := s.perms.Require(ctx, actor, perm.UsersApprove); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users WHERE status = ? ORDER BY created_at, id`, StatusPending)
	if err != nil {
		return nil, fmt.Errorf("auth: list pending: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// Approve activates a pending account.
func (s *Service) Approve(ctx context.Context, actor, userID int64) error {
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := perm.RequireOutranks(ctx, tx, actor, userID, perm.UsersApprove); err != nil {
			return err
		}
		now := s.now()
		res, err := tx.ExecContext(ctx, `UPDATE users SET status = ?, approved_at = ?, approved_by = ? WHERE id = ? AND status = ?`,
			StatusActive, store.FormatTime(now), actor, userID, StatusPending)
		if err != nil {
			return fmt.Errorf("auth: approve: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotPending
		}
		s.log.Info("account approved", "actor", actor, "user_id", userID)
		return audit.Record(ctx, tx, now, audit.Entry{Actor: actor, Action: audit.UserApproved, TargetType: "user", TargetID: userID})
	})
	if err == nil {
		s.publish(ctx, events.UserApproved, userID, actor)
	}
	return err
}

// Reject deletes a pending account and everything attached to it (keys,
// group memberships). Nothing about the rejected registration is kept
// beyond the audit entry.
func (s *Service) Reject(ctx context.Context, actor, userID int64) error {
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := perm.RequireOutranks(ctx, tx, actor, userID, perm.UsersApprove); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ? AND status = ?`, userID, StatusPending)
		if err != nil {
			return fmt.Errorf("auth: reject: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotPending
		}
		s.log.Info("account rejected", "actor", actor, "user_id", userID)
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: audit.UserRejected, TargetType: "user", TargetID: userID})
	})
	if err == nil {
		s.publish(ctx, events.UserRejected, userID, actor)
	}
	return err
}

// SetLocked locks or unlocks an active account. Locked accounts cannot log
// in by key or password. The last active administrator cannot be locked.
func (s *Service) SetLocked(ctx context.Context, actor, userID int64, locked bool) error {
	if actor == userID {
		return ErrSelf
	}
	from, to, action, topic := StatusActive, StatusLocked, audit.UserLocked, events.UserLocked
	if !locked {
		from, to, action, topic = StatusLocked, StatusActive, audit.UserUnlocked, events.UserUnlocked
	}
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := perm.RequireOutranks(ctx, tx, actor, userID, perm.UsersManage); err != nil {
			return err
		}
		checkAdmins, err := perm.AdminGuard(ctx, tx)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE users SET status = ? WHERE id = ? AND status = ?`, to, userID, from)
		if err != nil {
			return fmt.Errorf("auth: set status: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("auth: account is not %s: %w", from, ErrNotFound)
		}
		if err := checkAdmins(); err != nil {
			return err
		}
		s.log.Info("account status changed", "actor", actor, "user_id", userID, "status", to)
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: action, TargetType: "user", TargetID: userID})
	})
	if err == nil {
		s.publish(ctx, topic, userID, actor)
	}
	return err
}

// MaxListUsers bounds ListUsers results.
const MaxListUsers = 200

// ListUsers returns accounts whose username starts with prefix (all if
// empty), up to MaxListUsers, for administrators holding core.users.manage
// or core.groups.manage.
func (s *Service) ListUsers(ctx context.Context, actor int64, prefix string) ([]User, error) {
	set, err := s.perms.Permissions(ctx, actor)
	if err != nil {
		return nil, err
	}
	if !set.Has(perm.UsersManage) && !set.Has(perm.GroupsManage) {
		return nil, perm.ErrForbidden
	}
	// Escape LIKE wildcards so the prefix is matched literally.
	esc := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(NormalizeUsername(prefix))
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users WHERE username LIKE ? ESCAPE '\' ORDER BY username LIMIT ?`,
		esc+"%", MaxListUsers)
	if err != nil {
		return nil, fmt.Errorf("auth: list users: %w", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DB returns the database handle, for read-only listings (such as the audit
// log) whose permission checks the caller performs.
func (s *Service) DB() *sql.DB { return s.db }

// Usernames returns the usernames of the given accounts. Accounts that no
// longer exist are absent from the map.
func (s *Service) Usernames(ctx context.Context, ids []int64) (map[int64]string, error) {
	out := map[int64]string{}
	if len(ids) == 0 {
		return out, nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, username FROM users WHERE id IN (`+ph+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("auth: usernames: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}

// Member is the public view of an account used in member directories. It
// deliberately has no email, status details or login times.
type Member struct {
	ID       int64
	Username string
	Since    time.Time // registration date
}

// MaxMembersPage bounds a Members page.
const MaxMembersPage = 100

// Members lists active accounts whose username starts with prefix, sorted
// by username, and the total number matching. Any logged-in member may call
// it.
func (s *Service) Members(ctx context.Context, prefix string, offset, limit int) ([]Member, int, error) {
	limit = min(max(limit, 1), MaxMembersPage)
	esc := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(NormalizeUsername(prefix)) + "%"
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE status = ? AND username LIKE ? ESCAPE '\'`,
		StatusActive, esc).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("auth: count members: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, created_at FROM users WHERE status = ? AND username LIKE ? ESCAPE '\'
		ORDER BY username LIMIT ? OFFSET ?`, StatusActive, esc, limit, max(offset, 0))
	if err != nil {
		return nil, 0, fmt.Errorf("auth: list members: %w", err)
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		var since string
		if err := rows.Scan(&m.ID, &m.Username, &since); err != nil {
			return nil, 0, err
		}
		if m.Since, err = store.ParseTime(since); err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	return out, total, rows.Err()
}
