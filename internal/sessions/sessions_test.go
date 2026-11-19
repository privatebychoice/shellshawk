package sessions

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/presence"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

func TestListAndEnd(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "s.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// 1 admin; 2 moderator granted core.sessions.manage; 3 member;
	// 4 another moderator (same rank as 2).
	const (
		admin int64 = iota + 1
		mod
		member
		mod2
	)
	for _, q := range []string{
		`INSERT INTO users (id, username, password_hash, status, created_at) VALUES
			(1, 'ada', 'x', 'active', '2026-01-01T00:00:00Z'), (2, 'mo', 'x', 'active', '2026-01-01T00:00:00Z'),
			(3, 'mem', 'x', 'active', '2026-01-01T00:00:00Z'), (4, 'mo2', 'x', 'active', '2026-01-01T00:00:00Z')`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT 1, id FROM access_groups WHERE name = 'admin'`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT u, id FROM access_groups, (SELECT 2 AS u UNION SELECT 4) WHERE name = 'moderator'`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT u, id FROM access_groups, (SELECT 2 AS u UNION SELECT 3 UNION SELECT 4) WHERE name = 'member'`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	moderators, err := perm.NewService(db, perm.NewRegistry(), nil, log).GroupByName(ctx, perm.GroupModerator)
	if err != nil {
		t.Fatal(err)
	}

	conns := presence.NewConns(nil)
	s := NewService(db, conns, nil, log)
	ended := map[uint64]error{}
	open := func(uid int64) uint64 {
		var id uint64
		c, err := conns.Open(uid, "member", 0, func(cause error) { ended[id] = cause })
		if err != nil {
			t.Fatal(err)
		}
		id = c.ID()
		return id
	}
	adminConn, memberConn, mod2Conn, regConn := open(admin), open(member), open(mod2), open(0)

	// Moderators need the permission granted to their group.
	if _, err := s.List(ctx, mod); !errors.Is(err, perm.ErrForbidden) {
		t.Fatalf("moderator without the permission: err = %v", err)
	}
	if _, err := db.Exec(`INSERT INTO access_group_permissions (group_id, permission) VALUES (?, ?)`, moderators.ID, perm.SessionsManage); err != nil {
		t.Fatal(err)
	}
	list, err := s.List(ctx, mod)
	if err != nil || len(list) != 4 || list[0].Username != "ada" || list[1].Username != "mem" || list[3].Username != "" {
		t.Fatalf("list = %+v, %v", list, err)
	}

	tests := []struct {
		name  string
		actor int64
		conn  uint64
		want  error
	}{
		{"member cannot end connections", member, adminConn, perm.ErrForbidden},
		{"moderator cannot end an administrator's", mod, adminConn, perm.ErrForbidden},
		{"moderator ends a member's", mod, memberConn, nil},
		{"moderator ends another moderator's", mod, mod2Conn, nil},
		{"moderator ends a registration", mod, regConn, nil},
		{"already closed", mod, 999, ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := s.End(ctx, tt.actor, tt.conn)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
			var d *presence.Disconnect
			gotEnded := errors.As(ended[tt.conn], &d) && d.Message == EndedMessage
			if gotEnded != (tt.want == nil) {
				t.Errorf("connection ended = %v, cause %v", gotEnded, ended[tt.conn])
			}
		})
	}
	var n int
	db.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'connection.ended' AND actor_id = 2`).Scan(&n)
	if n != 3 {
		t.Errorf("audit entries = %d, want 3", n)
	}
}

func TestWebSessions(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "s.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO users (id, username, password_hash, status, created_at) VALUES
			(1, 'ada', 'x', 'active', '2026-01-01T00:00:00Z'), (3, 'mem', 'x', 'active', '2026-01-01T00:00:00Z')`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT 1, id FROM access_groups WHERE name = 'admin'`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT 3, id FROM access_groups WHERE name = 'member'`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	ps := perm.NewService(db, perm.NewRegistry(), nil, log)
	// Sessions are listed oldest first and stored to the second, so each
	// is created a second after the last for a fixed order.
	clock := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	tick := func() time.Time { clock = clock.Add(time.Second); return clock }
	web := websess.NewService(db, auth.NewService(db, ps, "new", nil, log), tick, log)
	s := NewService(db, presence.NewConns(nil), nil, log)
	if list, err := s.WebSessions(ctx, 1); err != nil || list != nil || s.HasWeb() {
		t.Fatalf("without web: %v, %v", list, err)
	}
	s.SetWeb(web)
	_, memSess, _ := web.Create(ctx, 3)
	_, adaSess, _ := web.Create(ctx, 1)

	if _, err := s.WebSessions(ctx, 3); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member listing: err = %v", err)
	}
	list, err := s.WebSessions(ctx, 1)
	if err != nil || len(list) != 2 || list[0].Username != "mem" || list[1].ID != adaSess.ID {
		t.Fatalf("list = %+v, %v", list, err)
	}
	tests := []struct {
		name  string
		actor int64
		id    string
		want  error
	}{
		{"member cannot", 3, adaSess.ID, perm.ErrForbidden},
		{"admin logs a member out", 1, memSess.ID, nil},
		{"already ended", 1, memSess.ID, ErrNotFound},
		{"unknown", 1, "nope", ErrNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := s.EndWeb(ctx, tt.actor, tt.id); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	var n int
	db.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'web_session.ended' AND actor_id = 1 AND target_id = '3'`).Scan(&n)
	if n != 1 {
		t.Errorf("audit entries = %d, want 1", n)
	}
}
