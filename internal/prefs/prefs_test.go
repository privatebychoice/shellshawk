package prefs

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/theme"
)

func TestPrefs(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "p.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO users (id, username, password_hash, status, created_at) VALUES (1, 'u1', 'x', 'active', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	cat, _ := theme.Builtin()
	s := NewService(db, cat, nil)

	got, err := s.Get(ctx, 1)
	if err != nil || got != Default() {
		t.Fatalf("Get default = %+v, %v", got, err)
	}

	tests := []struct {
		name string
		p    Prefs
		ok   bool
	}{
		{"valid", Prefs{Profile: theme.ProfilePutty, Theme: "amber", Bold: theme.EmphColor, PageSize: 30, ASCIIOnly: true}, true},
		{"unknown profile", Prefs{Profile: "vt52", Theme: "amber", PageSize: 30}, false},
		{"unknown theme", Prefs{Profile: theme.ProfileModern, Theme: "pink", PageSize: 30}, false},
		{"bad emphasis", Prefs{Profile: theme.ProfileModern, Theme: "amber", Italic: "sparkle", PageSize: 30}, false},
		{"page size too small", Prefs{Profile: theme.ProfileModern, Theme: "amber", PageSize: 1}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.Set(ctx, 1, tt.p)
			if (err == nil) != tt.ok {
				t.Fatalf("Set err = %v, ok %v", err, tt.ok)
			}
			if !tt.ok && !errors.Is(err, ErrInvalid) {
				t.Errorf("err = %v, want ErrInvalid", err)
			}
		})
	}
	got, _ = s.Get(ctx, 1)
	if got.Profile != theme.ProfilePutty || got.Theme != "amber" || !got.ASCIIOnly || got.Bold != theme.EmphColor {
		t.Errorf("round trip = %+v", got)
	}

	st := s.Styler(got)
	if st.Profile.Bold != theme.EmphColor || st.Profile.Unicode || st.Theme.Name != "amber" {
		t.Errorf("styler overrides not applied: %+v", st.Profile)
	}

	// A theme removed after being chosen falls back to the default.
	db.Exec(`UPDATE user_prefs SET theme = 'gone' WHERE user_id = 1`)
	got, _ = s.Get(ctx, 1)
	if got.Theme != theme.DefaultTheme {
		t.Errorf("missing theme fallback = %q", got.Theme)
	}
}
