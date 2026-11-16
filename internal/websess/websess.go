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
	"go.privatebychoice.com/shellshawk/internal/store"
)

// Lifetimes.
const (
	CodeTTL    = 5 * time.Minute
	SessionTTL = 12 * time.Hour
	codeBytes  = 5 // 40 bits: 8 characters, single use, short-lived, rate limited
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
	b := make([]byte, codeBytes)
	if _, err := rand.Read(b); err != nil {
		return "", time.Time{}, err
	}
	raw := crockford.EncodeToString(b)
	code := raw[:4] + "-" + raw[4:]
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
	u, err := s.auth.UserByUsername(ctx, username)
	if err != nil || u.Status != auth.StatusActive {
		return 0, ErrInvalidCode
	}
	var userID int64
	err = store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
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
		if userID != u.ID || expires <= store.FormatTime(s.now()) {
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
	if _, err := s.db.ExecContext(ctx, `INSERT INTO web_sessions (token_hash, user_id, csrf, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		hash(tok), userID, csrf, store.FormatTime(now), store.FormatTime(sess.ExpiresAt)); err != nil {
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
	err := s.db.QueryRowContext(ctx, `SELECT user_id, csrf, expires_at FROM web_sessions WHERE token_hash = ?`, hash(tok)).
		Scan(&sess.UserID, &sess.CSRF, &expires)
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
	return sess, nil
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
