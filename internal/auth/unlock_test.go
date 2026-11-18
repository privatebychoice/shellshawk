package auth

import (
	"errors"
	"testing"
)

func TestUnlockByOperator(t *testing.T) {
	f := newFixture(t)
	admin2 := f.user("sysadmin2", "admin")
	active := f.user("active1")
	erasing := f.user("erasing1")
	if err := f.svc.SetLocked(f.ctx, f.admin, erasing, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO erasure_requests (user_id, requested_at, erase_after, delete_content) VALUES (?, '2026-11-16T00:00:00Z', '2026-11-30T00:00:00Z', 0)`, erasing); err != nil {
		t.Fatal(err)
	}
	// A second administrator locks the first: the case the CLI recovers.
	if err := f.svc.SetLocked(f.ctx, admin2, f.admin, true); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		username string
		wantErr  error
		wantID   int64 // the account found, also on failure
	}{
		{"locked administrator", "SysAdmin1", nil, f.admin},
		{"already active", "active1", ErrNotFound, active},
		{"no such account", "nobody", ErrNotFound, 0},
		{"waiting to be erased", "erasing1", ErrErasurePending, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u, err := f.svc.UnlockByOperator(f.ctx, tt.username)
			if !errors.Is(err, tt.wantErr) || u.ID != tt.wantID {
				t.Errorf("UnlockByOperator = %d, %v; want %d, %v", u.ID, err, tt.wantID, tt.wantErr)
			}
		})
	}
	if u, _ := f.svc.UserByID(f.ctx, f.admin); u.Status != StatusActive {
		t.Errorf("administrator status = %s", u.Status)
	}
	var actor any
	if err := f.db.QueryRow(`SELECT actor_id FROM audit_log WHERE action = 'user.unlocked' AND target_id = ?`, f.admin).Scan(&actor); err != nil || actor != nil {
		t.Errorf("audit actor = %v, %v; want the system (NULL)", actor, err)
	}
}
