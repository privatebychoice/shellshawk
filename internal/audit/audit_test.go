package audit

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/store"
)

func TestRecordAndPurge(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "a.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	entries := []struct {
		at time.Time
		e  Entry
	}{
		{now.AddDate(-2, 0, 0), Entry{Actor: 1, Action: UserApproved, TargetType: "user", TargetID: 2}},
		{now.AddDate(0, -6, 0), Entry{Actor: SystemActor, Action: InviteCreated, TargetType: "invite", TargetID: 3}},
		{now, Entry{Actor: 1, Action: GroupCreated}},
	}
	for _, x := range entries {
		if err := Record(ctx, db, x.at, x.e); err != nil {
			t.Fatal(err)
		}
	}

	var nullActors int
	db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log WHERE actor_id IS NULL`).Scan(&nullActors)
	if nullActors != 1 {
		t.Errorf("system actor rows with NULL actor_id = %d, want 1", nullActors)
	}

	recs, err := Recent(ctx, db, 10)
	if err != nil || len(recs) != 3 {
		t.Fatalf("Recent = %d, %v", len(recs), err)
	}
	if recs[0].Action != GroupCreated || recs[0].Actor != "#1" || recs[1].Actor != "system" {
		t.Errorf("Recent order/actors = %+v", recs)
	}

	n, err := Purge(ctx, db, now, 365*24*time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("Purge = %d, %v; want 1", n, err)
	}
	var left int
	db.QueryRowContext(ctx, `SELECT count(*) FROM audit_log`).Scan(&left)
	if left != 2 {
		t.Errorf("rows left = %d, want 2", left)
	}
}
