package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/sshd"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// MaxKeysPerUser is the most public keys an account may hold.
const MaxKeysPerUser = 3

const maxKeyLabelLen = 64

// Key errors.
var (
	ErrKeyInvalid  = errors.New("not a valid SSH public key")
	ErrKeyInUse    = errors.New("that key is already registered")
	ErrKeyLimit    = fmt.Errorf("an account can have at most %d keys", MaxKeysPerUser)
	ErrKeyNotFound = errors.New("key not found")
)

// Key is a registered public key.
type Key struct {
	ID          int64
	Fingerprint string
	PublicKey   string // authorized_keys format, without comment
	Type        string
	Label       string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
}

// ParsePublicKey parses one authorized_keys line (options are not allowed)
// and checks it against the SSH user key policy. The comment, if any, is
// returned for use as a default label.
func ParsePublicKey(line string) (ssh.PublicKey, string, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return nil, "", ErrKeyInvalid
	}
	key, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil || len(options) > 0 || len(strings.TrimSpace(string(rest))) > 0 {
		return nil, "", ErrKeyInvalid
	}
	if err := sshd.CheckUserKey(key); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrKeyInvalid, err)
	}
	return key, comment, nil
}

func cleanLabel(label string) string {
	label = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(label))
	if r := []rune(label); len(r) > maxKeyLabelLen {
		label = string(r[:maxKeyLabelLen])
	}
	return label
}

// addKey inserts a key for userID inside tx, enforcing the per-user limit
// and global uniqueness.
func addKey(ctx context.Context, tx store.DBTX, now time.Time, userID int64, key ssh.PublicKey, label string) (int64, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM user_keys WHERE user_id = ?`, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("auth: count keys: %w", err)
	}
	if count >= MaxKeysPerUser {
		return 0, ErrKeyLimit
	}
	fp := ssh.FingerprintSHA256(key)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	res, err := tx.ExecContext(ctx, `
		INSERT INTO user_keys (user_id, fingerprint, key_type, public_key, label, created_at)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (fingerprint) DO NOTHING`,
		userID, fp, key.Type(), pub, cleanLabel(label), store.FormatTime(now))
	if err != nil {
		return 0, fmt.Errorf("auth: add key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, ErrKeyInUse
	}
	id, _ := res.LastInsertId()
	if err := audit.Record(ctx, tx, now, audit.Entry{Actor: userID, Action: audit.KeyAdded, TargetType: "key", TargetID: id, Detail: fp}); err != nil {
		return 0, err
	}
	return id, nil
}

// AddKey adds a public key (authorized_keys line) to the user's account.
// An empty label defaults to the key's comment.
func (s *Service) AddKey(ctx context.Context, userID int64, line, label string) (Key, error) {
	key, comment, err := ParsePublicKey(line)
	if err != nil {
		return Key{}, err
	}
	if strings.TrimSpace(label) == "" {
		label = comment
	}
	var id int64
	err = store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		var status string
		if err := tx.QueryRowContext(ctx, `SELECT status FROM users WHERE id = ?`, userID).Scan(&status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if status == StatusLocked {
			return fmt.Errorf("auth: account is locked")
		}
		id, err = addKey(ctx, tx, s.now(), userID, key, label)
		return err
	})
	if err != nil {
		return Key{}, err
	}
	s.log.Info("key added", "user_id", userID, "key_type", key.Type(), "fingerprint", ssh.FingerprintSHA256(key))
	return s.keyByID(ctx, userID, id)
}

// RemoveKey deletes one of the user's keys.
func (s *Service) RemoveKey(ctx context.Context, userID, keyID int64) error {
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		var fp string
		err := tx.QueryRowContext(ctx, `DELETE FROM user_keys WHERE id = ? AND user_id = ? RETURNING fingerprint`, keyID, userID).Scan(&fp)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrKeyNotFound
		}
		if err != nil {
			return fmt.Errorf("auth: remove key: %w", err)
		}
		s.log.Info("key removed", "user_id", userID, "fingerprint", fp)
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: userID, Action: audit.KeyRemoved, TargetType: "key", TargetID: keyID, Detail: fp})
	})
}

// ChangePassword replaces an active member's password, checking the
// policy. The caller makes sure the member is who they say (the BBS asks
// for a fresh key login). It is audited without any detail.
func (s *Service) ChangePassword(ctx context.Context, userID int64, pw string) error {
	if err := ValidatePassword(pw); err != nil {
		return err
	}
	hash, err := HashPassword(ctx, pw)
	if err != nil {
		return err
	}
	var username string
	err = store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `UPDATE users SET password_hash = ? WHERE id = ? AND status = ? RETURNING username`,
			hash, userID, StatusActive).Scan(&username); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return fmt.Errorf("auth: change password: %w", err)
		}
		s.log.Info("password changed", "user_id", userID)
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: userID, Action: audit.PasswordChanged, TargetType: "user", TargetID: userID})
	})
	if err != nil {
		return err
	}
	s.hookMu.Lock()
	hooks := append([]func(string){}, s.passwordHooks...)
	s.hookMu.Unlock()
	for _, fn := range hooks {
		fn(username)
	}
	return nil
}

const keyColumns = `id, fingerprint, public_key, key_type, label, created_at, last_used_at`

func scanKey(row interface{ Scan(...any) error }) (Key, error) {
	var k Key
	var created string
	var used sql.NullString
	if err := row.Scan(&k.ID, &k.Fingerprint, &k.PublicKey, &k.Type, &k.Label, &created, &used); err != nil {
		return Key{}, err
	}
	var err error
	if k.CreatedAt, err = store.ParseTime(created); err != nil {
		return Key{}, err
	}
	k.LastUsedAt, err = store.ScanNullTime(used)
	return k, err
}

func (s *Service) keyByID(ctx context.Context, userID, keyID int64) (Key, error) {
	k, err := scanKey(s.db.QueryRowContext(ctx, `SELECT `+keyColumns+` FROM user_keys WHERE id = ? AND user_id = ?`, keyID, userID))
	if errors.Is(err, sql.ErrNoRows) {
		return Key{}, ErrKeyNotFound
	}
	return k, err
}

// Keys lists the user's keys, oldest first.
func (s *Service) Keys(ctx context.Context, userID int64) ([]Key, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+keyColumns+` FROM user_keys WHERE user_id = ? ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: list keys: %w", err)
	}
	defer rows.Close()
	var out []Key
	for rows.Next() {
		k, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
