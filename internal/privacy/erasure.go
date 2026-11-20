package privacy

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// Erasure errors.
var (
	ErrNoRequest      = errors.New("there is no pending erasure request for this account")
	ErrAlreadyErased  = errors.New("this account has already been erased")
	ErrLastAdminErase = errors.New("the only active administrator cannot erase their account; make someone else an administrator first")
)

// Erasure is a pending or completed erasure request.
type Erasure struct {
	UserID        int64
	RequestedAt   time.Time
	EraseAfter    time.Time
	DeleteContent bool
	CompletedAt   *time.Time
}

// Grace returns the configured grace period.
func (s *Service) Grace() time.Duration { return s.grace }

// RequestErasure locks the member's account at once and schedules its
// erasure after the grace period. deleteContent records the member's
// choice for posts and chat lines. It then publishes ErasureRequested, so
// the account's connections, including the one that asked, and its web
// sessions end, as when an account is locked.
func (s *Service) RequestErasure(ctx context.Context, userID int64, deleteContent bool) (Erasure, error) {
	now := s.now()
	e := Erasure{UserID: userID, RequestedAt: now, EraseAfter: now.Add(s.grace), DeleteContent: deleteContent}
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		checkAdmins, err := perm.AdminGuard(ctx, tx)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE users SET status = ? WHERE id = ? AND status = ?`, auth.StatusLocked, userID, auth.StatusActive)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("privacy: account %d is not active", userID)
		}
		if err := checkAdmins(); err != nil {
			return ErrLastAdminErase
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO erasure_requests (user_id, requested_at, erase_after, delete_content) VALUES (?, ?, ?, ?)`,
			userID, store.FormatTime(now), store.FormatTime(e.EraseAfter), deleteContent); err != nil {
			return fmt.Errorf("privacy: erasure request: %w", err)
		}
		return audit.Record(ctx, tx, now, audit.Entry{Actor: userID, Action: audit.ErasureRequested, TargetType: "user", TargetID: userID})
	})
	if err != nil {
		return Erasure{}, err
	}
	s.log.Info("erasure requested", "user_id", userID, "erase_after", e.EraseAfter)
	s.publish(ctx, events.Event{Topic: events.ErasureRequested, UserID: userID, Actor: userID, EraseAfter: e.EraseAfter})
	return e, nil
}

// Erasure returns the erasure request for a member, if any.
func (s *Service) Erasure(ctx context.Context, userID int64) (Erasure, bool, error) {
	var e Erasure
	var req, after string
	var done sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT user_id, requested_at, erase_after, delete_content, completed_at FROM erasure_requests WHERE user_id = ?`, userID).
		Scan(&e.UserID, &req, &after, &e.DeleteContent, &done)
	if errors.Is(err, sql.ErrNoRows) {
		return Erasure{}, false, nil
	}
	if err != nil {
		return Erasure{}, false, err
	}
	if e.RequestedAt, err = store.ParseTime(req); err != nil {
		return Erasure{}, false, err
	}
	if e.EraseAfter, err = store.ParseTime(after); err != nil {
		return Erasure{}, false, err
	}
	e.CompletedAt, err = store.ScanNullTime(done)
	return e, true, err
}

// CancelErasure withdraws a pending request and reactivates the account.
// Members cannot log in while locked, so they ask an administrator, who
// needs core.users.manage.
func (s *Service) CancelErasure(ctx context.Context, actor, userID int64) error {
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := perm.RequireOutranks(ctx, tx, actor, userID, perm.UsersManage); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM erasure_requests WHERE user_id = ? AND completed_at IS NULL`, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNoRequest
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET status = ? WHERE id = ?`, auth.StatusActive, userID); err != nil {
			return err
		}
		s.log.Info("erasure cancelled", "actor", actor, "user_id", userID)
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: audit.ErasureCancelled, TargetType: "user", TargetID: userID})
	})
	if err == nil {
		s.publish(ctx, events.Event{Topic: events.UserUnlocked, UserID: userID, Actor: actor})
	}
	return err
}

// Publisher delivers the erasure event to plugins. *events.Bus implements it.
type Publisher interface {
	Publish(ctx context.Context, e events.Event) error
}

// RunDue erases every account whose grace period has ended and returns how
// many were erased. For each, plugins handle UserErased first; if any of
// them fails, that account is left for the next run.
func (s *Service) RunDue(ctx context.Context, pub Publisher) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT user_id, delete_content FROM erasure_requests
		WHERE completed_at IS NULL AND erase_after <= ?`, store.FormatTime(s.now()))
	if err != nil {
		return 0, fmt.Errorf("privacy: due erasures: %w", err)
	}
	type due struct {
		id  int64
		del bool
	}
	var list []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.del); err != nil {
			rows.Close()
			return 0, err
		}
		list = append(list, d)
	}
	rows.Close()
	done := 0
	for _, d := range list {
		if err := pub.Publish(ctx, events.Event{Topic: events.UserErased, UserID: d.id, DeleteContent: d.del}); err != nil {
			s.log.Error("erasure postponed: a plugin could not remove the member's data", "user_id", d.id, "err", err)
			continue
		}
		if err := s.anonymise(ctx, d.id); err != nil {
			s.log.Error("erasure failed", "user_id", d.id, "err", err)
			continue
		}
		done++
	}
	return done, nil
}

// anonymise turns the account into a tombstone: a random "former-" name,
// no credentials, keys, email, profile, preferences or groups. The row is
// kept so content the member chose to keep (and messages they sent, and
// audit entries) stays attributed to the same anonymous name.
func (s *Service) anonymise(ctx context.Context, userID int64) error {
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		var name string
		for range 5 {
			var b [4]byte
			if _, err := rand.Read(b[:]); err != nil {
				return err
			}
			name = auth.TombstonePrefix + hex.EncodeToString(b[:])
			var taken bool
			if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE username = ?)`, name).Scan(&taken); err != nil {
				return err
			}
			if !taken {
				break
			}
		}
		// "!" can never be produced by HashPassword, so no password matches.
		if _, err := tx.ExecContext(ctx, `UPDATE users SET username = ?, password_hash = '!erased', email = NULL, status = ?,
			last_login_at = NULL, approved_by = NULL, invite_id = NULL WHERE id = ?`, name, auth.StatusLocked, userID); err != nil {
			return err
		}
		for _, q := range []string{
			`DELETE FROM user_keys WHERE user_id = ?`,
			`DELETE FROM user_prefs WHERE user_id = ?`,
			`DELETE FROM user_profiles WHERE user_id = ?`,
			`DELETE FROM user_visibility WHERE user_id = ?`,
			`DELETE FROM user_access_groups WHERE user_id = ?`,
		} {
			if _, err := tx.ExecContext(ctx, q, userID); err != nil {
				return err
			}
		}
		now := s.now()
		if _, err := tx.ExecContext(ctx, `UPDATE erasure_requests SET completed_at = ? WHERE user_id = ?`, store.FormatTime(now), userID); err != nil {
			return err
		}
		s.log.Info("account erased", "user_id", userID)
		return audit.Record(ctx, tx, now, audit.Entry{Actor: audit.SystemActor, Action: audit.UserErased, TargetType: "user", TargetID: userID})
	})
}

// ExportSource is core's part of the data export: account.json.
func (s *Service) ExportSource() export.Source {
	return export.Source{Name: "", Export: s.exportAccount}
}

func (s *Service) exportAccount(ctx context.Context, userID int64) ([]export.File, error) {
	u, err := s.auth.UserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	p, err := s.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	groups, err := s.perms.UserGroups(ctx, userID)
	if err != nil {
		return nil, err
	}
	keys, err := s.auth.Keys(ctx, userID)
	if err != nil {
		return nil, err
	}
	type keyOut struct {
		Label       string     `json:"label"`
		Type        string     `json:"type"`
		Fingerprint string     `json:"fingerprint"`
		PublicKey   string     `json:"public_key"`
		Added       time.Time  `json:"added"`
		LastUsed    *time.Time `json:"last_used"`
	}
	var ks []keyOut
	for _, k := range keys {
		ks = append(ks, keyOut{k.Label, k.Type, k.Fingerprint, k.PublicKey, k.CreatedAt, k.LastUsedAt})
	}
	vis := map[string]string{}
	for f, l := range p.Visibility {
		vis[string(f)] = string(l)
	}
	f, err := export.JSON("account.json", map[string]any{
		"username": u.Username, "status": u.Status, "registered": u.CreatedAt, "last_login": u.LastLoginAt,
		"email": u.Email, "full_name": p.FullName, "phone": p.Phone, "status_message": p.Status,
		"visibility": vis, "groups": groups, "ssh_keys": ks,
	})
	return []export.File{f}, err
}
