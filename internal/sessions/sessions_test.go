package sessions

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/presence"
	"go.privatebychoice.com/shellshawk/internal/store"
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
