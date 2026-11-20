package polls

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugins/plugintest"
)

func setup(t *testing.T) (*Plugin, *plugintest.Env) {
	t.Helper()
	p := New()
	return p, plugintest.New(t, p)
}

func TestCreateValidation(t *testing.T) {
	p, e := setup(t)
	alice := e.User("alice")
	ok := Spec{Question: "Lunch?", Options: []string{"Pizza", "Soup"}, CreatorID: alice}
	mod := func(f func(*Spec)) Spec { s := ok; s.Options = append([]string(nil), ok.Options...); f(&s); return s }
	tests := []struct {
		name string
		s    Spec
		want error
	}{
		{"valid", ok, nil},
		{"blank lines ignored", mod(func(s *Spec) { s.Options = []string{"", "A", " ", "B", ""} }), nil},
		{"one option", mod(func(s *Spec) { s.Options = []string{"A"} }), ErrInvalid},
		{"duplicate option", mod(func(s *Spec) { s.Options = []string{"A", "a"} }), ErrInvalid},
		{"too many options", mod(func(s *Spec) { s.Options = []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"} }), ErrInvalid},
		{"escape in question", mod(func(s *Spec) { s.Question = "Q\x1b[2J" }), ErrInvalid},
		{"open too long", mod(func(s *Spec) { s.ClosesIn = (MaxOpenDays + 1) * 24 * time.Hour }), ErrInvalid},
		{"bad context", mod(func(s *Spec) { s.Context = "Bad Context" }), ErrInvalid},
		{"pin without manage", mod(func(s *Spec) { s.Pinned = true }), perm.ErrForbidden},
		{"admin may pin", mod(func(s *Spec) { s.Pinned = true; s.CreatorID = e.Admin }), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := p.Create(e.Ctx, tt.s); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVoting(t *testing.T) {
	p, e := setup(t)
	alice, bob := e.User("alice"), e.User("bob")
	single, _ := p.Create(e.Ctx, Spec{Question: "One?", Options: []string{"A", "B"}, CreatorID: alice})
	multi, _ := p.Create(e.Ctx, Spec{Question: "Many?", Options: []string{"X", "Y", "Z"}, Multi: true, Named: true, CreatorID: alice})
	sp, _ := p.Get(e.Ctx, bob, single)
	mp, _ := p.Get(e.Ctx, bob, multi)
	a, b := sp.Options[0].ID, sp.Options[1].ID

	tests := []struct {
		name string
		poll int64
		opts []int64
		want error
	}{
		{"two options on single choice", single, []int64{a, b}, ErrBadVote},
		{"no option", single, nil, ErrBadVote},
		{"option of another poll", single, []int64{mp.Options[0].ID}, ErrBadVote},
		{"valid", single, []int64{a}, nil},
		{"change vote", single, []int64{b}, nil},
		{"multi", multi, []int64{mp.Options[0].ID, mp.Options[2].ID, mp.Options[0].ID}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := p.Vote(e.Ctx, bob, tt.poll, tt.opts); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}

	sp, _ = p.Get(e.Ctx, bob, single)
	if sp.Options[0].Votes != 0 || sp.Options[1].Votes != 1 || sp.Voters != 1 || len(sp.MyVotes) != 1 {
		t.Errorf("single tally after change = %+v", sp)
	}
	if sp.Options[1].Voters != nil {
		t.Error("anonymous poll exposed voter names")
	}
	mp, _ = p.Get(e.Ctx, alice, multi)
	if mp.Options[0].Votes != 1 || mp.Options[2].Votes != 1 || mp.Voters != 1 || len(mp.Options[0].Voters) != 1 || mp.Options[0].Voters[0] != "bob" {
		t.Errorf("named multi tally = %+v", mp)
	}

	// Results visibility: alice (creator) yes, carol (not voted) no.
	carol := e.User("carol")
	set, _ := e.Perms.Permissions(e.Ctx, carol)
	cp, _ := p.Get(e.Ctx, carol, single)
	if p.CanSeeResults(cp, carol, set) {
		t.Error("non-voter sees results of an open poll")
	}
	aset, _ := e.Perms.Permissions(e.Ctx, alice)
	if ap, _ := p.Get(e.Ctx, alice, single); !p.CanSeeResults(ap, alice, aset) {
		t.Error("creator cannot see results")
	}
}

func TestCloseExpiryAndManage(t *testing.T) {
	p, e := setup(t)
	alice, bob := e.User("alice"), e.User("bob")
	mod := e.User("mod1", perm.GroupModerator)
	id, _ := p.Create(e.Ctx, Spec{Question: "Q?", Options: []string{"A", "B"}, ClosesIn: time.Hour, CreatorID: alice})
	pl, _ := p.Get(e.Ctx, bob, id)

	if err := p.Close(e.Ctx, bob, id); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("non-creator close err = %v", err)
	}
	if err := p.SetPinned(e.Ctx, alice, id, true); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("creator pin err = %v (pinning needs polls.manage)", err)
	}
	if err := p.SetPinned(e.Ctx, mod, id, true); err != nil {
		t.Errorf("moderator pin: %v", err)
	}
	if open, _ := p.List(e.Ctx, true); len(open) != 1 || !open[0].Pinned {
		t.Errorf("open list = %+v", open)
	}

	// Expiry closes voting without anyone acting.
	p.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if err := p.Vote(e.Ctx, bob, id, []int64{pl.Options[0].ID}); !errors.Is(err, ErrClosed) {
		t.Errorf("vote after expiry err = %v", err)
	}
	if open, _ := p.List(e.Ctx, true); len(open) != 0 {
		t.Error("expired poll still listed as open")
	}
	if closed, _ := p.List(e.Ctx, false); len(closed) != 1 {
		t.Error("expired poll not listed as closed")
	}
	set, _ := e.Perms.Permissions(e.Ctx, bob)
	if bp, _ := p.Get(e.Ctx, bob, id); !p.CanSeeResults(bp, bob, set) {
		t.Error("results hidden after the poll closed")
	}
	if err := p.Delete(e.Ctx, alice, id); err != nil {
		t.Errorf("creator delete: %v", err)
	}
	if _, err := p.Get(e.Ctx, bob, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("get after delete err = %v", err)
	}
}

func TestVotesSurviveAccountDeletion(t *testing.T) {
	p, e := setup(t)
	alice := e.User("alice")
	id, _ := p.Create(e.Ctx, Spec{Question: "Q?", Options: []string{"A", "B"}, CreatorID: alice})
	pl, _ := p.Get(e.Ctx, alice, id)
	if err := p.Vote(e.Ctx, alice, id, []int64{pl.Options[0].ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.DB.Exec(`DELETE FROM users WHERE id = ?`, alice); err != nil {
		t.Fatal(err)
	}
	pl, _ = p.Get(e.Ctx, e.Admin, id)
	if pl.Options[0].Votes != 1 || pl.Creator != "former member" {
		t.Errorf("after deletion = %+v (totals must be kept, link removed)", pl)
	}
}

// TestOpenPollLimit: a member can have at most the set number of their own
// polls open; closed or expired ones do not count, and poll managers are
// not limited.
func TestOpenPollLimit(t *testing.T) {
	p, e := setup(t)
	alice, mod := e.User("alice"), e.User("mod1", perm.GroupModerator)
	if errs, err := p.h.Settings.Save(e.Ctx, e.Admin, form.Values{setMaxOpen: "2"}); err != nil || len(errs) > 0 {
		t.Fatal(errs, err)
	}
	spec := func(who int64, closesIn time.Duration) Spec {
		return Spec{Question: "Lunch?", Options: []string{"Pizza", "Soup"}, CreatorID: who, ClosesIn: closesIn}
	}
	first, err := p.Create(e.Ctx, spec(alice, 0))
	if err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name string
		do   func() error
		msg  string // "" = allowed
	}{
		{"second", func() error { _, err := p.Create(e.Ctx, spec(alice, time.Hour)); return err }, ""},
		{"third, over the limit", func() error { _, err := p.Create(e.Ctx, spec(alice, 0)); return err }, "you have reached the limit of open polls (2)"},
		{"a poll manager is not limited", func() error {
			for range 3 {
				if _, err := p.Create(e.Ctx, spec(mod, 0)); err != nil {
					return err
				}
			}
			return nil
		}, ""},
		{"closing one frees a place", func() error {
			if err := p.Close(e.Ctx, alice, first); err != nil {
				return err
			}
			_, err := p.Create(e.Ctx, spec(alice, 0))
			return err
		}, ""},
		{"an expired one frees a place too", func() error {
			p.now = func() time.Time { return time.Now().Add(2 * time.Hour) } // the second has closed itself
			_, err := p.Create(e.Ctx, spec(alice, 0))
			return err
		}, ""},
	}
	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			err := st.do()
			if st.msg == "" && err != nil || st.msg != "" && (err == nil || !strings.Contains(err.Error(), st.msg)) {
				t.Errorf("err = %v, want %q", err, st.msg)
			}
		})
	}
}
