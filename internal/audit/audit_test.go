package audit

import (
	"context"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
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

func TestBeforePaging(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "a.db"), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	// Five entries; two share a timestamp, and one was inserted later with
	// an earlier time, so paging must follow time, then insertion order.
	for i, at := range []time.Time{base, base.Add(time.Minute), base.Add(time.Minute), base.Add(2 * time.Minute), base.Add(-time.Minute)} {
		if err := Record(ctx, db, at, Entry{Actor: SystemActor, Action: "test", Detail: strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	var before int64
	for page := 0; page < 5; page++ {
		recs, err := Before(ctx, db, before, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) == 0 {
			break
		}
		for _, r := range recs {
			got = append(got, r.Detail)
		}
		before = recs[len(recs)-1].ID
	}
	if want := "3 2 1 0 4"; strings.Join(got, " ") != want {
		t.Errorf("pages = %v, want %s", got, want)
	}
	if recs, err := Before(ctx, db, 999, 2); err != nil || len(recs) != 0 {
		t.Errorf("unknown cursor = %v, %v", recs, err)
	}
}
