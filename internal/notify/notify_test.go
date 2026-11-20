package notify

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

const ann, bob = 1, 2

// clock is a settable test clock.
type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func setup(t *testing.T) (*Service, *clock, context.Context) {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "n.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO users (id, username, password_hash, status, created_at) VALUES
		(1, 'ann', 'x', 'active', '2026-01-01T00:00:00Z'), (2, 'bob', 'x', 'active', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	ps := perm.NewService(db, perm.NewRegistry(), nil, log)
	c := &clock{t: time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)}
	s := NewService(db, auth.NewService(db, ps, "new", nil, log), c.now, log)
	for _, k := range []Kind{
		{Name: "chat:page", Label: "Pages", Default: true},
		{Name: "polls:closed", Label: "Closed polls", Default: false},
	} {
		if err := s.Register(k); err != nil {
			t.Fatal(err)
		}
	}
	return s, c, ctx
}

func TestRegister(t *testing.T) {
	s, _, _ := setup(t)
	tests := []struct {
		name string
		kind Kind
		ok   bool
	}{
		{"valid", Kind{Name: "messages:new", Label: "New messages"}, true},
		{"duplicate", Kind{Name: "chat:page", Label: "Pages"}, false},
		{"no plugin", Kind{Name: "page", Label: "Pages"}, false},
		{"upper case", Kind{Name: "Chat:Page", Label: "Pages"}, false},
		{"no label", Kind{Name: "chat:other"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.Register(tt.kind); (err == nil) != tt.ok || (err != nil && !errors.Is(err, ErrInvalid)) {
				t.Errorf("Register = %v, want ok %v", err, tt.ok)
			}
		})
	}
}

func TestAddFollowsSettings(t *testing.T) {
	s, _, ctx := setup(t)
	add := func(kind string) bool {
		t.Helper()
		_, ok, err := s.Add(ctx, New{UserID: bob, Kind: kind, ActorID: ann, Text: "hi"})
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	tests := []struct {
		name string
		set  map[string]bool
		kind string
		want bool
	}{
		{"on by default", nil, "chat:page", true},
		{"off by default", nil, "polls:closed", false},
		{"unknown kind", nil, "chat:nope", false},
		{"turned off", map[string]bool{"chat:page": false}, "chat:page", false},
		{"turned on", map[string]bool{"polls:closed": true}, "polls:closed", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.set != nil {
				if err := s.SetSettings(ctx, bob, tt.set); err != nil {
					t.Fatal(err)
				}
			}
			if got := add(tt.kind); got != tt.want {
				t.Errorf("added = %v, want %v", got, tt.want)
			}
		})
	}
	if err := s.SetSettings(ctx, bob, map[string]bool{"chat:nope": true}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown kind setting = %v", err)
	}
	got, err := s.Settings(ctx, bob)
	if err != nil || got["chat:page"] || !got["polls:closed"] || len(got) != 2 {
		t.Errorf("settings = %v, %v", got, err)
	}
	if _, _, err := s.Add(ctx, New{UserID: bob, Kind: "polls:closed", Ref: strings.Repeat("x", MaxRef+1)}); !errors.Is(err, ErrInvalid) {
		t.Errorf("long ref = %v", err)
	}
}

func TestLifecycle(t *testing.T) {
	s, c, ctx := setup(t)
	add := func(text string) int64 {
		t.Helper()
		id, ok, err := s.Add(ctx, New{UserID: bob, Kind: "chat:page", ActorID: ann, Text: text, Ref: "7"})
		if err != nil || !ok {
			t.Fatal(ok, err)
		}
		c.t = c.t.Add(time.Second)
		return id
	}
	first := add("would like to talk\x1b[2J in   #lobby")
	second := add(strings.Repeat("é", MaxText+5))

	n, err := s.Get(ctx, bob, first)
	if err != nil || n.Actor != "ann" || n.Text != "would like to talk[2J in #lobby" || n.Ref != "7" || n.Seen {
		t.Errorf("first = %+v, %v", n, err)
	}
	if got := s.Describe(n); got != "Pages, from ann: would like to talk[2J in #lobby" {
		t.Errorf("Describe = %q", got)
	}
	if n, _ := s.Get(ctx, bob, second); len([]rune(n.Text)) != MaxText || !strings.HasSuffix(n.Text, "…") {
		t.Errorf("long text = %q", n.Text)
	}
	if _, err := s.Get(ctx, ann, first); !errors.Is(err, ErrNotFound) {
		t.Errorf("another member's notification = %v", err)
	}

	if un, _ := s.Unseen(ctx, bob); len(un) != 2 || un[0].ID != first {
		t.Errorf("unseen = %+v", un)
	}
	if err := s.MarkSeen(ctx, bob, first); err != nil {
		t.Fatal(err)
	}
	if k, _ := s.CountUnseen(ctx, bob); k != 1 {
		t.Errorf("count after marking one = %d", k)
	}
	if err := s.MarkSeen(ctx, bob); err != nil {
		t.Fatal(err)
	}
	if k, _ := s.CountUnseen(ctx, bob); k != 0 {
		t.Errorf("count after marking all = %d", k)
	}
	if list, _ := s.List(ctx, bob); len(list) != 2 || list[0].ID != second || !list[0].Seen {
		t.Errorf("list = %+v", list)
	}
	if err := s.Delete(ctx, ann, first); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting another member's = %v", err)
	}
	if err := s.Delete(ctx, bob, first); err != nil {
		t.Fatal(err)
	}
	if n, err := s.DeleteAll(ctx, bob); n != 1 || err != nil {
		t.Errorf("DeleteAll = %d, %v", n, err)
	}
}

func TestPrune(t *testing.T) {
	s, c, ctx := setup(t)
	for range Keep + 5 {
		if _, _, err := s.Add(ctx, New{UserID: bob, Kind: "chat:page"}); err != nil {
			t.Fatal(err)
		}
		c.t = c.t.Add(time.Minute)
	}
	if list, _ := s.List(ctx, bob); len(list) != Keep {
		t.Errorf("kept %d, want %d", len(list), Keep)
	}
	c.t = c.t.Add(MaxAge + time.Hour)
	if list, _ := s.List(ctx, bob); len(list) != 0 {
		t.Errorf("kept %d past MaxAge", len(list))
	}
}

func TestErasure(t *testing.T) {
	s, _, ctx := setup(t)
	bus := events.New(slog.New(slog.DiscardHandler))
	s.Subscribe(bus)
	for _, n := range []New{{UserID: bob, Kind: "chat:page", ActorID: ann}, {UserID: ann, Kind: "chat:page", ActorID: bob}, {UserID: bob, Kind: "chat:page"}} {
		if _, _, err := s.Add(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetSettings(ctx, ann, map[string]bool{"chat:page": false}); err != nil {
		t.Fatal(err)
	}
	if err := bus.Publish(ctx, events.Event{Topic: events.UserErased, UserID: ann}); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.List(ctx, ann); len(list) != 0 {
		t.Errorf("erased member keeps %d", len(list))
	}
	if list, _ := s.List(ctx, bob); len(list) != 1 || list[0].ActorID != 0 {
		t.Errorf("bob keeps %+v; want only the one not from ann", list)
	}
	if on, _ := s.Enabled(ctx, ann, "chat:page"); !on {
		t.Error("erased member's settings kept")
	}
}

func TestExport(t *testing.T) {
	s, _, ctx := setup(t)
	if _, _, err := s.Add(ctx, New{UserID: bob, Kind: "chat:page", ActorID: ann, Text: "hello"}); err != nil {
		t.Fatal(err)
	}
	files, err := s.ExportSource().Export(ctx, bob)
	if err != nil || len(files) != 1 || files[0].Name != "notifications.json" {
		t.Fatalf("export = %+v, %v", files, err)
	}
	body := string(files[0].Data)
	for _, want := range []string{`"kind": "chat:page"`, `"from": "ann"`, `"text": "hello"`, `"polls:closed": false`} {
		if !strings.Contains(body, want) {
			t.Errorf("export missing %s:\n%s", want, body)
		}
	}
}

func TestAge(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		ago  time.Duration
		want string
	}{
		{10 * time.Second, "just now"},
		{time.Minute, "1 minute ago"},
		{59 * time.Minute, "59 minutes ago"},
		{time.Hour, "1 hour ago"},
		{47 * time.Hour, "47 hours ago"},
		{72 * time.Hour, "3 days ago"},
	}
	for _, tt := range tests {
		if got := Age(now.Add(-tt.ago), now); got != tt.want {
			t.Errorf("Age(%v) = %q, want %q", tt.ago, got, tt.want)
		}
	}
}

func TestRefPath(t *testing.T) {
	path := RefPath("/m/")
	tests := []struct{ ref, want string }{
		{"12", "/m/12"},
		{"", ""},
		{"0", ""},
		{"-3", ""},
		{"12/../x", ""},
		{"+12", ""},
	}
	for _, tt := range tests {
		if got := path(Notification{Ref: tt.ref}); got != tt.want {
			t.Errorf("RefPath(%q) = %q, want %q", tt.ref, got, tt.want)
		}
	}
}
