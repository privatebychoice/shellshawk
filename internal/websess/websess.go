// Package websess issues one-time web login codes (generated in the TUI) and
// manages web sessions. SSH keys remain the identity: the web never uses
// passwords (docs/DESIGN.md §11).
package websess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// Lifetimes.
const (
	CodeTTL    = 5 * time.Minute
	SessionTTL = 12 * time.Hour
	// touchEvery bounds how often a session's last activity is written.
	touchEvery = time.Minute
	// CodeChars is the length of a login code: 12 Crockford characters,
	// 60 bits. That is too many to guess in the minutes a code lives even
	// from millions of addresses, so wrong codes never block a member or
	// void their code; only each address's attempts are limited.
	CodeChars = 12
)

// Errors.
var (
	ErrInvalidCode = errors.New("that code is not valid; codes work once and expire after a few minutes")
	ErrNoSession   = errors.New("not logged in")
)

var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

func hash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// normalizeCode uppercases, drops separators and maps Crockford aliases.
func normalizeCode(c string) string {
	return strings.NewReplacer("-", "", " ", "", "O", "0", "I", "1", "L", "1").Replace(strings.ToUpper(strings.TrimSpace(c)))
}

// Service stores codes and sessions.
type Service struct {
	db   *sql.DB
	auth *auth.Service
	now  func() time.Time
	log  *slog.Logger
}

// NewService returns a Service. now may be nil.
func NewService(db *sql.DB, a *auth.Service, now func() time.Time, log *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, auth: a, now: now, log: log.With("component", "websess")}
}

// NewCode creates a one-time login code for an active member, replacing any
// earlier unused code. The code is shown once and stored only as a hash.
func (s *Service) NewCode(ctx context.Context, userID int64) (string, time.Time, error) {
	u, err := s.auth.UserByID(ctx, userID)
	if err != nil {
		return "", time.Time{}, err
	}
	if u.Status != auth.StatusActive {
		return "", time.Time{}, fmt.Errorf("websess: account is not active")
	}
	b := make([]byte, 8) // 64 random bits; the first 60 make the code
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	raw := crockford.EncodeToString(b)[:CodeChars]
	code := raw[:4] + "-" + raw[4:8] + "-" + raw[8:]
	expires := s.now().Add(CodeTTL)
	err = store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM web_login_codes WHERE user_id = ? OR expires_at <= ?`, userID, store.FormatTime(s.now())); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO web_login_codes (code_hash, user_id, expires_at) VALUES (?, ?, ?)`,
			hash(normalizeCode(code)), userID, store.FormatTime(expires))
		return err
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("websess: new code: %w", err)
	}
	s.log.Info("web login code issued", "user_id", userID)
	return code, expires, nil
}

// Redeem consumes a code for username and returns the member's ID. A code
// works once, only for the member it was issued to, and only while the
// account is active.
func (s *Service) Redeem(ctx context.Context, username, code string) (int64, error) {
	// An unknown or inactive account still goes through the same lookup
	// below, so the time taken does not tell whether a username exists.
	var want int64
	if u, err := s.auth.UserByUsername(ctx, username); err == nil && u.Status == auth.StatusActive {
		want = u.ID
	}
	var userID int64
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		var expires string
		h := hash(normalizeCode(code))
		err := tx.QueryRowContext(ctx, `SELECT user_id, expires_at FROM web_login_codes WHERE code_hash = ?`, h).Scan(&userID, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidCode
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM web_login_codes WHERE code_hash = ?`, h); err != nil {
			return err
		}
		if want == 0 || userID != want || expires <= store.FormatTime(s.now()) {
			return ErrInvalidCode
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return userID, nil
}

// Session is a logged-in web session.
type Session struct {
	ID        string // random and not secret; names the session to staff
	UserID    int64
	CSRF      string
	ExpiresAt time.Time
}

func token(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Create starts a session and returns its secret token (for the cookie).
func (s *Service) Create(ctx context.Context, userID int64) (string, Session, error) {
	tok, err := token(32)
	if err != nil {
		return "", Session{}, err
	}
	csrf, err := token(24)
	if err != nil {
		return "", Session{}, err
	}
	now := s.now()
	sess := Session{UserID: userID, CSRF: csrf, ExpiresAt: now.Add(SessionTTL)}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE expires_at <= ?`, store.FormatTime(now)); err != nil {
		return "", Session{}, err
	}
	pub := make([]byte, 9)
	if _, err := rand.Read(pub); err != nil {
		return "", Session{}, err
	}
	sess.ID = hex.EncodeToString(pub)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO web_sessions (token_hash, user_id, csrf, created_at, expires_at, last_seen_at, public_id) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		hash(tok), userID, csrf, store.FormatTime(now), store.FormatTime(sess.ExpiresAt), store.FormatTime(now), sess.ID); err != nil {
		return "", Session{}, fmt.Errorf("websess: create: %w", err)
	}
	s.log.Info("web session started", "user_id", userID)
	return tok, sess, nil
}

// Lookup returns the session for a token. Expired sessions, and sessions of
// accounts that are no longer active, are not valid.
func (s *Service) Lookup(ctx context.Context, tok string) (Session, error) {
	if tok == "" {
		return Session{}, ErrNoSession
	}
	var sess Session
	var expires string
	var seen sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT public_id, user_id, csrf, expires_at, last_seen_at FROM web_sessions WHERE token_hash = ?`, hash(tok)).
		Scan(&sess.ID, &sess.UserID, &sess.CSRF, &expires, &seen)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNoSession
	}
	if err != nil {
		return Session{}, err
	}
	if sess.ExpiresAt, err = store.ParseTime(expires); err != nil {
		return Session{}, err
	}
	if !s.now().Before(sess.ExpiresAt) {
		return Session{}, ErrNoSession
	}
	u, err := s.auth.UserByID(ctx, sess.UserID)
	if err != nil || u.Status != auth.StatusActive {
		return Session{}, ErrNoSession
	}
	s.touch(ctx, sess.ID, seen)
	return sess, nil
}

// touch records that a session was used, at most once per touchEvery so
// most requests write nothing. A failure only costs accuracy.
func (s *Service) touch(ctx context.Context, id string, seen sql.NullString) {
	now := s.now()
	if seen.Valid {
		if t, err := store.ParseTime(seen.String); err == nil && now.Sub(t) < touchEvery {
			return
		}
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE web_sessions SET last_seen_at = ? WHERE public_id = ?`, store.FormatTime(now), id); err != nil {
		s.log.Warn("record web session activity", "err", err)
	}
}

// Info describes a web session for staff. It never includes the token.
type Info struct {
	ID       string
	UserID   int64
	Created  time.Time
	LastSeen time.Time // Created for sessions from before activity was recorded
	Expires  time.Time
}

// List returns the unexpired web sessions, oldest first.
func (s *Service) List(ctx context.Context) ([]Info, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT public_id, user_id, created_at, ifnull(last_seen_at, created_at), expires_at
		FROM web_sessions WHERE expires_at > ? ORDER BY created_at, public_id`, store.FormatTime(s.now()))
	if err != nil {
		return nil, fmt.Errorf("websess: list: %w", err)
	}
	defer rows.Close()
	var out []Info
	for rows.Next() {
		var i Info
		var created, seen, expires string
		if err := rows.Scan(&i.ID, &i.UserID, &created, &seen, &expires); err != nil {
			return nil, err
		}
		for _, f := range []struct {
			s string
			t *time.Time
		}{{created, &i.Created}, {seen, &i.LastSeen}, {expires, &i.Expires}} {
			if *f.t, err = store.ParseTime(f.s); err != nil {
				return nil, err
			}
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// Get returns one unexpired web session, or ErrNoSession.
func (s *Service) Get(ctx context.Context, id string) (Info, error) {
	all, err := s.List(ctx)
	if err != nil {
		return Info{}, err
	}
	for _, i := range all {
		if i.ID == id {
			return i, nil
		}
	}
	return Info{}, ErrNoSession
}

// DeleteByID ends one session, or reports ErrNoSession.
func (s *Service) DeleteByID(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE public_id = ?`, id)
	if err != nil {
		return fmt.Errorf("websess: delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoSession
	}
	return nil
}

// Delete ends a session.
func (s *Service) Delete(ctx context.Context, tok string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE token_hash = ?`, hash(tok))
	return err
}

// CheckCSRF compares a submitted token with the session's in constant time.
func CheckCSRF(sess Session, submitted string) bool {
	return submitted != "" && subtle.ConstantTimeCompare([]byte(sess.CSRF), []byte(submitted)) == 1
}

// DeleteUser ends every web session of an account and deletes its unused
// login codes. It returns how many sessions there were.
func (s *Service) DeleteUser(ctx context.Context, userID int64) (int64, error) {
	var n int64
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM web_sessions WHERE user_id = ?`, userID)
		if err != nil {
			return fmt.Errorf("websess: delete sessions: %w", err)
		}
		n, _ = res.RowsAffected()
		if _, err := tx.ExecContext(ctx, `DELETE FROM web_login_codes WHERE user_id = ?`, userID); err != nil {
			return fmt.Errorf("websess: delete codes: %w", err)
		}
		return nil
	})
	return n, err
}

// Subscribe makes locking an account end its web sessions, so unlocking it
// later does not bring them back; the member logs in afresh. (A locked
// account's sessions are refused anyway, by Lookup.)
func (s *Service) Subscribe(bus *events.Bus) {
	for _, topic := range []string{events.UserLocked, events.ErasureRequested} {
		bus.Subscribe(topic, "websess", func(ctx context.Context, e events.Event) error {
			n, err := s.DeleteUser(ctx, e.UserID)
			if err != nil {
				return err
			}
			if n > 0 {
				s.log.Info("web sessions of locked account ended", "event", topic, "user_id", e.UserID, "count", n)
			}
			return nil
		})
	}
}
