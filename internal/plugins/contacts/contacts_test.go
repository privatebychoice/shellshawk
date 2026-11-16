package contacts

import (
	"errors"
	"slices"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/plugins/plugintest"
)

func names(cs []Contact) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.Username)
	}
	return out
}

func TestContacts(t *testing.T) {
	p := New()
	e := plugintest.New(t, p)
	alice, bob := e.User("alice"), e.User("bob")
	e.User("carol")

	tests := []struct {
		name  string
		owner int64
		user  string
		note  string
		want  error
	}{
		{"add bob", alice, "Bob", "met at the meetup", nil},
		{"add carol", alice, "carol", "", nil},
		{"duplicate", alice, "bob", "", ErrExists},
		{"self", alice, "alice", "", ErrSelf},
		{"unknown", alice, "nobody", "", ErrUnknownUser},
		{"note with escape", alice, "admin1", "x\x1b[2J", ErrInvalid},
		{"bob adds alice back", bob, "alice", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := p.Add(e.Ctx, tt.owner, tt.user, tt.note); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}

	list, err := p.List(e.Ctx, alice)
	if err != nil || !slices.Equal(names(list), []string{"bob", "carol"}) {
		t.Fatalf("list = %v, %v", names(list), err)
	}
	if !list[0].Mutual || list[1].Mutual || list[0].Note != "met at the meetup" {
		t.Errorf("mutual/note wrong: %+v", list)
	}
	if ok, _ := p.IsFriend(e.Ctx, alice, bob); !ok {
		t.Error("alice and bob should be friends")
	}
	carol := list[1].UserID
	if ok, _ := p.IsFriend(e.Ctx, alice, carol); ok {
		t.Error("one-sided contact counted as a friend")
	}
	if ok, _ := p.IsContact(e.Ctx, carol, alice); ok {
		t.Error("IsContact direction wrong")
	}

	if err := p.SetNote(e.Ctx, alice, bob, "updated"); err != nil {
		t.Fatal(err)
	}
	if err := p.SetNote(e.Ctx, bob, carol, "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("note on non-contact err = %v", err)
	}
	if err := p.Remove(e.Ctx, alice, carol); err != nil {
		t.Fatal(err)
	}
	if err := p.Remove(e.Ctx, alice, carol); !errors.Is(err, ErrNotFound) {
		t.Errorf("second remove err = %v", err)
	}
}

func TestGroups(t *testing.T) {
	p := New()
	e := plugintest.New(t, p)
	alice, bob, carol := e.User("alice"), e.User("bob"), e.User("carol")
	p.Add(e.Ctx, alice, "bob", "")
	p.Add(e.Ctx, alice, "carol", "")

	g, err := p.CreateGroup(e.Ctx, alice, "Book club")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.CreateGroup(e.Ctx, alice, "book CLUB"); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate group err = %v", err)
	}
	if _, err := p.CreateGroup(e.Ctx, alice, "a,b"); !errors.Is(err, ErrInvalid) {
		t.Errorf("comma group err = %v", err)
	}
	if _, err := p.CreateGroup(e.Ctx, bob, "Book club"); err != nil {
		t.Errorf("another member's group with the same name: %v", err)
	}

	if err := p.AddToGroup(e.Ctx, alice, g, bob); err != nil {
		t.Fatal(err)
	}
	if err := p.AddToGroup(e.Ctx, alice, g, carol); err != nil {
		t.Fatal(err)
	}
	if err := p.AddToGroup(e.Ctx, alice, g, e.Admin); !errors.Is(err, ErrNotFound) {
		t.Errorf("adding a non-contact err = %v", err)
	}
	if err := p.AddToGroup(e.Ctx, bob, g, alice); !errors.Is(err, ErrNotFound) {
		t.Errorf("using someone else's group err = %v", err)
	}

	ids, err := p.GroupMemberIDs(e.Ctx, alice, "BOOK club")
	if err != nil || len(ids) != 2 {
		t.Fatalf("GroupMemberIDs = %v, %v", ids, err)
	}
	if _, err := p.GroupMemberIDs(e.Ctx, carol, "Book club"); !errors.Is(err, ErrNotFound) {
		t.Errorf("other member's group err = %v", err)
	}

	// Removing a contact removes it from the group.
	p.Remove(e.Ctx, alice, carol)
	members, _ := p.GroupMembers(e.Ctx, alice, g)
	if !slices.Equal(names(members), []string{"bob"}) {
		t.Errorf("members after contact removal = %v", names(members))
	}
	gs, _ := p.Groups(e.Ctx, alice)
	if len(gs) != 1 || gs[0].Members != 1 {
		t.Errorf("groups = %+v", gs)
	}
	if err := p.DeleteGroup(e.Ctx, bob, g); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleting another member's group err = %v", err)
	}
	if err := p.DeleteGroup(e.Ctx, alice, g); err != nil {
		t.Fatal(err)
	}
	if list, _ := p.List(e.Ctx, alice); len(list) != 1 {
		t.Error("deleting a group removed contacts")
	}
}
