package messages

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/tui"
)

func TestNotifications(t *testing.T) {
	f := setup(t)
	// bob turns message notifications off; carol keeps the default.
	if err := f.Notify.SetSettings(f.Ctx, f.bob, map[string]bool{NotifyNew: false}); err != nil {
		t.Fatal(err)
	}
	id, err := f.p.Send(f.Ctx, f.alice, Draft{To: "bob, carol, alice", Subject: "Lunch?", Body: "Noon at the usual place."})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		user int64
		want int
	}{
		{"recipient with the default", f.carol, 1},
		{"recipient who turned them off", f.bob, 0},
		{"sender writing to themselves too", f.alice, 0},
	}
	for _, tt := range tests {
		list, err := f.Notify.List(f.Ctx, tt.user)
		if err != nil || len(list) != tt.want {
			t.Errorf("%s: %d notification(s), %v; want %d", tt.name, len(list), err, tt.want)
		}
	}
	list, _ := f.Notify.List(f.Ctx, f.carol)
	n := list[0]
	if n.Kind != NotifyNew || n.Actor != "alice" || n.Text != "Lunch?" || n.Ref != strconv.FormatInt(id, 10) {
		t.Errorf("notification = %+v", n)
	}

	k, ok := f.Registry.NotificationKind(NotifyNew)
	if !ok || k.Open == nil || k.OpenLabel != "Read the message" {
		t.Fatalf("kind = %+v, %v", k, ok)
	}
	// Opening shows the message; q leaves its actions.
	s := f.Session(f.carol, "\rq\r")
	if err := k.Open(f.Ctx, s, n); err != nil && !errors.Is(err, tui.ErrCancelled) {
		t.Fatal(err)
	}
	if !strings.Contains(s.Out.String(), "Noon at the usual place.") {
		t.Errorf("opened:\n%s", s.Out.String())
	}
	// Deleted for good: the notification says so.
	if err := f.p.Delete(f.Ctx, f.carol, id, Inbox); err != nil {
		t.Fatal(err)
	}
	if err := f.p.DeleteForever(f.Ctx, f.carol, id); err != nil {
		t.Fatal(err)
	}
	s = f.Session(f.carol, "\r")
	if err := k.Open(f.Ctx, s, n); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s.Out.String(), "That message is no longer in your inbox.") {
		t.Errorf("deleted message:\n%s", s.Out.String())
	}
}
