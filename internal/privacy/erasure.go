package privacy

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
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
		// The anonymous name is chosen first so plugins can write it where
		// the member's username appears in stored text.
		name, err := s.tombstoneName(ctx)
		if err != nil {
			s.log.Error("erasure postponed: no anonymous name", "user_id", d.id, "err", err)
			continue
		}
		if err := pub.Publish(ctx, events.Event{Topic: events.UserErased, UserID: d.id, DeleteContent: d.del, Tombstone: name}); err != nil {
			s.log.Error("erasure postponed: a plugin could not remove the member's data", "user_id", d.id, "err", err)
			continue
		}
		if err := s.anonymise(ctx, d.id, name); err != nil {
			s.log.Error("erasure failed", "user_id", d.id, "err", err)
			continue
		}
		done++
	}
	return done, nil
}

// tombstoneName picks an unused random "former-" name. It is random, not
// derived from the account, so an erased member cannot be re-identified.
func (s *Service) tombstoneName(ctx context.Context) (string, error) {
	for range 5 {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		name := auth.TombstonePrefix + hex.EncodeToString(b[:])
		var taken bool
		if err := s.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE username = ?)`, name).Scan(&taken); err != nil {
			return "", err
		}
		if !taken {
			return name, nil
		}
	}
	return "", errors.New("privacy: no free anonymous name")
}

// anonymise turns the account into a tombstone named name: no credentials,
// keys, email, profile, preferences or groups. The row is kept so content
// the member chose to keep (and messages they sent, and audit entries)
// stays attributed to the same anonymous name. Identifying details are
// also removed from records kept about the account: the key fingerprints
// in its key audit entries (public keys are often published, so a
// fingerprint could re-identify it) and the note on the invite it
// registered with (such as "for Alice Smith").
func (s *Service) anonymise(ctx context.Context, userID int64, name string) error {
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE invites SET note = '' WHERE id = (SELECT invite_id FROM users WHERE id = ?)`, userID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE audit_log SET detail = '' WHERE actor_id = ? AND action IN (?, ?)`,
			userID, audit.KeyAdded, audit.KeyRemoved); err != nil {
			return err
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
	display, err := s.exportPrefs(ctx, userID)
	if err != nil {
		return nil, err
	}
	invites, err := s.exportInvites(ctx, userID)
	if err != nil {
		return nil, err
	}
	entries, err := s.exportAudit(ctx, userID)
	if err != nil {
		return nil, err
	}
	f, err := export.JSON("account.json", map[string]any{
		"username": u.Username, "status": u.Status, "registered": u.CreatedAt, "last_login": u.LastLoginAt,
		"email": u.Email, "full_name": p.FullName, "phone": p.Phone, "status_message": p.Status,
		"visibility": vis, "groups": groups, "ssh_keys": ks,
		"display_settings": display, "invites_issued": invites, "audit_entries": entries,
	})
	return []export.File{f}, err
}

// exportPrefs returns the member's display settings, or nil if they have
// never changed the defaults.
func (s *Service) exportPrefs(ctx context.Context, userID int64) (map[string]any, error) {
	var profile, theme, bold, italic, updated string
	var ascii, transitions, notifications bool
	var pageSize int
	err := s.db.QueryRowContext(ctx, `SELECT profile, theme, bold, italic, ascii_only, page_size, transitions, notifications, updated_at
		FROM user_prefs WHERE user_id = ?`, userID).Scan(&profile, &theme, &bold, &italic, &ascii, &pageSize, &transitions, &notifications, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("privacy: export display settings: %w", err)
	}
	return map[string]any{"terminal_type": profile, "theme": theme, "bold": bold, "italic": italic, "ascii_only": ascii,
		"page_size": pageSize, "transitions": transitions, "notifications_between_screens": notifications, "updated": updated}, nil
}

// exportInvites returns the invites the member created. Codes are stored
// only as hashes and are not included.
func (s *Service) exportInvites(ctx context.Context, userID int64) ([]map[string]any, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT created_at, expires_at, max_uses, uses, require_approval, note, revoked_at
		FROM invites WHERE created_by = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("privacy: export invites: %w", err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var created, note string
		var expires, revoked sql.NullString
		var maxUses, uses int
		var approval bool
		if err := rows.Scan(&created, &expires, &maxUses, &uses, &approval, &note, &revoked); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"created": created, "expires": nullable(expires), "max_uses": maxUses, "uses": uses,
			"require_approval": approval, "note": note, "revoked": nullable(revoked)})
	}
	return out, rows.Err()
}

// exportAudit returns the audit log entries about the member: what they did
// and what was done to their account. Who acted is given only as "you",
// "another account" or "the system", so staff are not identified.
func (s *Service) exportAudit(ctx context.Context, userID int64) ([]map[string]any, error) {
	id := strconv.FormatInt(userID, 10)
	rows, err := s.db.QueryContext(ctx, `SELECT at, COALESCE(actor_id, 0), action, detail FROM audit_log
		WHERE actor_id = ? OR (target_type = 'user' AND target_id = ?) ORDER BY at, id`, userID, id)
	if err != nil {
		return nil, fmt.Errorf("privacy: export audit entries: %w", err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var at, action, detail string
		var actor int64
		if err := rows.Scan(&at, &actor, &action, &detail); err != nil {
			return nil, err
		}
		by := "another account"
		switch actor {
		case userID:
			by = "you"
		case audit.SystemActor:
			by = "the system"
		}
		out = append(out, map[string]any{"at": at, "action": action, "by": by, "detail": detail})
	}
	return out, rows.Err()
}

func nullable(v sql.NullString) any {
	if v.Valid {
		return v.String
	}
	return nil
}
