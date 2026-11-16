package settings

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

func TestBBSName(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "s.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// user 1 = admin, user 2 = member
	for _, q := range []string{
		`INSERT INTO users (id, username, password_hash, status, created_at) VALUES (1, 'a1', 'x', 'active', '2026-01-01T00:00:00Z'), (2, 'm1', 'x', 'active', '2026-01-01T00:00:00Z')`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT 1, id FROM access_groups WHERE name = 'admin'`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT 2, id FROM access_groups WHERE name = 'member'`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s := NewService(db, nil, log)
	if got := s.BBSName(ctx); got != DefaultBBSName {
		t.Errorf("default name = %q", got)
	}

	tests := []struct {
		name  string
		actor int64
		in    string
		want  error
	}{
		{"admin sets name", 1, "  Example Board ", nil},
		{"member forbidden", 2, "Mine", perm.ErrForbidden},
		{"empty", 1, "   ", ErrInvalid},
		{"too long", 1, strings.Repeat("x", MaxBBSNameLen+1), ErrInvalid},
		{"escape sequence", 1, "Board\x1b[31m", ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.SetBBSName(ctx, tt.actor, tt.in); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	if got := s.BBSName(ctx); got != "Example Board" {
		t.Errorf("name = %q", got)
	}
	var n int
	db.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'setting.changed'`).Scan(&n)
	if n != 1 {
		t.Errorf("audit entries = %d, want 1", n)
	}
}
