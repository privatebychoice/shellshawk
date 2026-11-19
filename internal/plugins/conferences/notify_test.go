package conferences

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

func TestReplyNotifications(t *testing.T) {
	f := setup(t)
	thread, _, err := f.p.StartThread(f.Ctx, f.alice, f.general, "Garden club", "Who is in?")
	if err != nil {
		t.Fatal(err)
	}
	modThread, _, err := f.p.StartThread(f.Ctx, f.mod, f.general, "House rules", "Be kind.")
	if err != nil {
		t.Fatal(err)
	}
	modGroup, _ := f.Perms.GroupByName(f.Ctx, perm.GroupModerator)

	// Each step adds to the counts the next one sees.
	steps := []struct {
		name   string
		setup  func()
		user   int64
		thread int64
		alice  int // alice's notifications afterwards
		mod    int
	}{
		{"someone else replies", nil, f.bob, thread, 1, 0},
		{"the author replies to their own thread", nil, f.alice, thread, 1, 0},
		{"a reply to the moderator's thread", nil, f.alice, modThread, 1, 1},
		{"the author can no longer read the thread", func() {
			if err := f.Perms.RemoveMember(f.Ctx, f.Admin, modGroup.ID, f.mod); err != nil {
				t.Fatal(err)
			}
		}, f.bob, modThread, 1, 1},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			if st.setup != nil {
				st.setup()
			}
			if _, err := f.p.Reply(f.Ctx, st.user, st.thread, "A reply."); err != nil {
				t.Fatal(err)
			}
			for who, want := range map[int64]int{f.alice: st.alice, f.mod: st.mod} {
				if list, _ := f.Notify.List(f.Ctx, who); len(list) != want {
					t.Errorf("user %d has %d notification(s), want %d", who, len(list), want)
				}
			}
		})
	}
	list, _ := f.Notify.List(f.Ctx, f.alice)
	n := list[0]
	if n.Kind != NotifyReply || n.Actor != "bob" || n.Text != "Garden club" || n.Ref != strconv.FormatInt(thread, 10) {
		t.Errorf("notification = %+v", n)
	}
	k, ok := f.Registry.NotificationKind(NotifyReply)
	if !ok || k.Open == nil {
		t.Fatalf("kind = %+v, %v", k, ok)
	}
	s := f.Session(f.alice, "\rq\r")
	if err := k.Open(f.Ctx, s, n); err != nil && !errors.Is(err, tui.ErrCancelled) {
		t.Fatal(err)
	}
	if !strings.Contains(s.Out.String(), "Garden club") || !strings.Contains(s.Out.String(), "A reply.") {
		t.Errorf("opened:\n%s", s.Out.String())
	}
	// A thread the member can no longer read is reported, not shown.
	gone := f.Session(f.alice, "\r")
	n.Ref = strconv.FormatInt(modThread+100, 10)
	if err := k.Open(f.Ctx, gone, n); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gone.Out.String(), "That thread no longer exists, or you can no longer read it.") {
		t.Errorf("missing thread:\n%s", gone.Out.String())
	}
}
