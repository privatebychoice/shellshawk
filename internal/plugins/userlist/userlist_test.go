package userlist

import (
	"testing"

	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/contacts"
	"go.privatebychoice.com/shellshawk/internal/plugins/messages"
	"go.privatebychoice.com/shellshawk/internal/plugins/plugintest"
	"go.privatebychoice.com/shellshawk/internal/presence"
)

func TestRelationsAndOnlineVisibility(t *testing.T) {
	c := contacts.New()
	m := messages.New(c)
	u := New(c, m)
	e := plugintest.New(t, c, m, u)
	pres := presence.New(nil)
	u.h.Presence = pres // the harness does not track presence

	alice, bob, carol := e.User("alice"), e.User("bob"), e.User("carol")
	c.Add(e.Ctx, alice, "bob", "")
	c.Add(e.Ctx, bob, "alice", "")   // friends
	c.Add(e.Ctx, alice, "carol", "") // one-sided
	defer pres.Enter(bob)()
	defer pres.Enter(carol)()

	tests := []struct {
		name          string
		viewer, other int64
		want          relation
		tag           string
	}{
		{"self", alice, alice, relation{self: true}, " (you)"},
		{"friend online", alice, bob, relation{contact: true, friend: true, online: true}, " (friend, online)"},
		{"one-sided contact: online hidden", alice, carol, relation{contact: true}, " (contact)"},
		{"stranger: online hidden", carol, bob, relation{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := u.relate(e.Ctx, tt.viewer, tt.other)
			if err != nil || got != tt.want || got.tag() != tt.tag {
				t.Errorf("relate = %+v %q, %v; want %+v %q", got, got.tag(), err, tt.want, tt.tag)
			}
		})
	}

	online, err := u.online(e.Ctx, alice)
	if err != nil || len(online) != 1 || online[0].Username != "bob" {
		t.Errorf("online friends = %+v, %v (carol is online but not a friend)", online, err)
	}
	var _ plugin.Plugin = u
}
