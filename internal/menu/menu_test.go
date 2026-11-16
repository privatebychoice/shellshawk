package menu

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

var defaults = []Default{
	{"core:settings", "Display settings"},
	{"core:admin", "Administration"},
	{TargetLogout, "Log out"},
}

func known(t string) bool {
	return slices.ContainsFunc(defaults, func(d Default) bool { return d.Target == t }) || t == "notes:main"
}

func setup(t *testing.T) (*Service, context.Context) {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "m.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, q := range []string{
		`INSERT INTO users (id, username, password_hash, status, created_at) VALUES (1, 'a1', 'x', 'active', '2026-01-01T00:00:00Z'), (2, 'm1', 'x', 'active', '2026-01-01T00:00:00Z')`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT 1, id FROM access_groups WHERE name = 'admin'`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT 2, id FROM access_groups WHERE name = 'member'`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	s := NewService(db, perm.NewService(db, perm.NewRegistry(), nil, log), nil, log)
	if err := s.Seed(ctx, defaults); err != nil {
		t.Fatal(err)
	}
	return s, ctx
}

func targets(t *testing.T, s *Service, ctx context.Context, parent int64) []string {
	t.Helper()
	es, err := s.Children(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		if e.Kind == KindSubmenu {
			out = append(out, "sub:"+e.Label)
		} else {
			out = append(out, e.Target)
		}
	}
	return out
}

func TestSeedPlacesNewItemsBeforeLogout(t *testing.T) {
	s, ctx := setup(t)
	if got := targets(t, s, ctx, 0); !slices.Equal(got, []string{"core:settings", "core:admin", TargetLogout}) {
		t.Fatalf("seeded = %v", got)
	}
	// A plugin appears later: it goes before Log out.
	if err := s.Seed(ctx, append(defaults, Default{"notes:main", "Notes"})); err != nil {
		t.Fatal(err)
	}
	if got := targets(t, s, ctx, 0); !slices.Equal(got, []string{"core:settings", "core:admin", "notes:main", TargetLogout}) {
		t.Errorf("after plugin = %v", got)
	}
	// Removed by an admin: not re-added on the next start.
	es, _ := s.Children(ctx, 0)
	if err := s.Delete(ctx, 1, es[2].ID); err != nil {
		t.Fatal(err)
	}
	s.Seed(ctx, append(defaults, Default{"notes:main", "Notes"}))
	if got := targets(t, s, ctx, 0); slices.Contains(got, "notes:main") {
		t.Errorf("removed item came back: %v", got)
	}
}

func TestEditing(t *testing.T) {
	s, ctx := setup(t)
	sub, err := s.Add(ctx, 1, Entry{Kind: KindSubmenu, Label: "More"}, known)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Add(ctx, 1, Entry{ParentID: sub, Kind: KindItem, Label: "Notes", Target: "notes:main"}, known); err != nil {
		t.Fatal(err)
	}
	if got := targets(t, s, ctx, sub); !slices.Equal(got, []string{"notes:main"}) {
		t.Errorf("submenu = %v", got)
	}
	es, _ := s.Children(ctx, 0)
	logout, admin := es[2], es[1]

	tests := []struct {
		name string
		do   func() error
		want error
	}{
		{"member cannot edit", func() error { _, err := s.Add(ctx, 2, Entry{Kind: KindSubmenu, Label: "x"}, known); return err }, perm.ErrForbidden},
		{"unknown target", func() error {
			_, err := s.Add(ctx, 1, Entry{Kind: KindItem, Label: "x", Target: "gone:main"}, known)
			return err
		}, ErrInvalid},
		{"unknown permission", func() error { return s.Update(ctx, 1, logout.ID, "Bye", "no.such") }, ErrInvalid},
		{"empty label", func() error { return s.Update(ctx, 1, logout.ID, "  ", "") }, ErrInvalid},
		{"escape in label", func() error { return s.Update(ctx, 1, logout.ID, "Bye\x1b[2J", "") }, ErrInvalid},
		{"item as parent", func() error {
			_, err := s.Add(ctx, 1, Entry{ParentID: logout.ID, Kind: KindSubmenu, Label: "x"}, known)
			return err
		}, ErrInvalid},
		{"logout protected", func() error { return s.Delete(ctx, 1, logout.ID) }, ErrProtected},
		{"admin protected", func() error { return s.Delete(ctx, 1, admin.ID) }, ErrProtected},
		{"non-empty submenu", func() error { return s.Delete(ctx, 1, sub) }, ErrNotEmpty},
		{"rename protected item is fine", func() error { return s.Update(ctx, 1, logout.ID, "Goodbye", "") }, nil},
		{"missing entry", func() error { return s.Delete(ctx, 1, 9999) }, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.do(); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}

	// Move "More" (last) up past Log out.
	if err := s.Move(ctx, 1, sub, -1); err != nil {
		t.Fatal(err)
	}
	if got := targets(t, s, ctx, 0); !slices.Equal(got, []string{"core:settings", "core:admin", "sub:More", TargetLogout}) {
		t.Errorf("after move = %v", got)
	}
	s.Move(ctx, 1, es[0].ID, -1) // already first: no-op
	if got := targets(t, s, ctx, 0); got[0] != "core:settings" {
		t.Errorf("moving first entry up changed order: %v", got)
	}

	if err := s.Reset(ctx, 1, defaults); err != nil {
		t.Fatal(err)
	}
	if got := targets(t, s, ctx, 0); !slices.Equal(got, []string{"core:settings", "core:admin", TargetLogout}) {
		t.Errorf("after reset = %v", got)
	}
}
