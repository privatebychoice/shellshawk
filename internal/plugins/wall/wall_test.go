package wall

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugins/plugintest"
)

type fixture struct {
	*plugintest.Env
	p               *Plugin
	alice, bob, mod int64
	now             time.Time
}

func setup(t *testing.T) *fixture {
	t.Helper()
	p := New()
	e := plugintest.New(t, p)
	f := &fixture{Env: e, p: p, alice: e.User("alice"), bob: e.User("bob"), mod: e.User("mod1", perm.GroupModerator),
		now: time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)}
	p.now = func() time.Time { return f.now }
	return f
}

func TestSet(t *testing.T) {
	f := setup(t)
	tests := []struct {
		name, text string
		want       error
	}{
		{"plain", "Hello wall", nil},
		{"emphasis", "Back *Monday*, **no calls**", nil},
		{"edit replaces", "  Changed my mind  ", nil},
		{"empty", "   ", ErrInvalid},
		{"only markers", "****", ErrInvalid},
		{"too long", strings.Repeat("x", MaxLine+1), ErrInvalid},
		{"escape sequence", "hi\x1b[2J", ErrInvalid},
		{"newline", "two\nlines", ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := f.p.Set(f.Ctx, f.alice, tt.text); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
	all, err := f.p.Entries(f.Ctx)
	if err != nil || len(all) != 1 || all[0].Text != "Changed my mind" || all[0].Username != "alice" {
		t.Errorf("entries = %+v, %v; want alice's one edited line", all, err)
	}

	// Without wall.write a member can still read but not write.
	g, _ := f.Perms.GroupByName(f.Ctx, perm.GroupMember)
	if err := f.Perms.Revoke(f.Ctx, f.Admin, g.ID, PermWrite); err != nil {
		t.Fatal(err)
	}
	if err := f.p.Set(f.Ctx, f.bob, "hi"); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("without permission err = %v", err)
	}
}

func TestExpiry(t *testing.T) {
	f := setup(t)
	start := f.now
	f.p.Set(f.Ctx, f.alice, "old line")
	f.now = start.Add(6 * 24 * time.Hour)
	f.p.Set(f.Ctx, f.bob, "newer line")

	if all, _ := f.p.Entries(f.Ctx); len(all) != 2 || all[0].Username != "bob" {
		t.Fatalf("entries = %+v, want bob's newer line first", all)
	}
	if e, ok, _ := f.p.Mine(f.Ctx, f.alice); !ok || !e.ExpiresAt.Equal(start.Add(DefaultExpiryHours*time.Hour)) {
		t.Errorf("alice's line = %+v, %v; want expiry 7 days after writing", e, ok)
	}

	f.now = start.Add(7*24*time.Hour + time.Minute)
	all, _ := f.p.Entries(f.Ctx)
	if len(all) != 1 || all[0].Username != "bob" {
		t.Errorf("after 7 days entries = %+v, want only bob's", all)
	}
	if n, err := f.p.PurgeExpired(f.Ctx); err != nil || n != 1 {
		t.Errorf("purged %d (err %v), want alice's expired line", n, err)
	}

	// Editing renews the line.
	f.p.Set(f.Ctx, f.bob, "still here")
	f.now = f.now.Add(6 * 24 * time.Hour)
	if _, ok, _ := f.p.Mine(f.Ctx, f.bob); !ok {
		t.Error("edited line expired early")
	}

	// The administrator setting controls the period.
	st := f.Registry.Plugins()[0].Settings
	if errs, err := st.Save(f.Ctx, f.Admin, form.Values{setExpiryHours: "1"}); err != nil || errs != nil {
		t.Fatal(errs, err)
	}
	if all, _ := f.p.Entries(f.Ctx); len(all) != 0 {
		t.Errorf("with a 1-hour expiry entries = %+v, want none", all)
	}
	for _, bad := range []string{"0", "8761"} {
		if errs, _ := st.Save(f.Ctx, f.Admin, form.Values{setExpiryHours: bad}); errs == nil {
			t.Errorf("expiry %s hours accepted", bad)
		}
	}
}

func TestRemove(t *testing.T) {
	f := setup(t)
	f.p.Set(f.Ctx, f.alice, "alice was here")
	f.p.Set(f.Ctx, f.bob, "bob was here")
	tests := []struct {
		name         string
		actor, owner int64
		want         error
	}{
		{"member removes another's", f.alice, f.bob, perm.ErrForbidden},
		{"member removes own", f.alice, f.alice, nil},
		{"already gone", f.alice, f.alice, ErrNotFound},
		{"moderator removes another's", f.mod, f.bob, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := f.p.Remove(f.Ctx, tt.actor, tt.owner); !errors.Is(err, tt.want) {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestPrivacy(t *testing.T) {
	f := setup(t)
	f.p.Set(f.Ctx, f.alice, "**mine**")
	files, err := f.p.export(f.Ctx, f.alice)
	if err != nil || len(files) != 1 || !strings.Contains(string(files[0].Data), `"text": "**mine**"`) {
		t.Fatalf("export = %s, %v", files[0].Data, err)
	}
	if err := f.p.erase(f.Ctx, events.Event{UserID: f.alice}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.p.Mine(f.Ctx, f.alice); ok {
		t.Error("erased member's line kept")
	}
}

func TestTUI(t *testing.T) {
	f := setup(t)
	f.p.Set(f.Ctx, f.bob, "Hi from **bob**")
	// Show the wall, Write my line (1), the line, show again, Back (5 of:
	// Edit, Remove, Find, Show again, Back).
	s := f.Session(f.alice, strings.Join([]string{"", "1", "Out *today*", "", "5"}, "\r")+"\r")
	if err := f.p.run(f.Ctx, s); err != nil {
		t.Fatalf("run: %v\n%s", err, s.Out)
	}
	out := s.Out.String()
	for _, want := range []string{"bob: Hi from bob (less than a minute ago)", "1. Write my line", "alice: Out today", "Your line expires in 7 days"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if strings.Contains(out, "**bob**") {
		t.Error("emphasis markers shown instead of the words")
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
	if e, ok, _ := f.p.Mine(f.Ctx, f.alice); !ok || e.Text != "Out *today*" {
		t.Errorf("saved line = %+v, %v", e, ok)
	}
}

func TestWebPage(t *testing.T) {
	f := setup(t)
	f.p.Set(f.Ctx, f.alice, "<script>x</script> **hi**")
	page, err := f.WebGet(f.p, "/", nil, f.bob)
	if err != nil {
		t.Fatal(err)
	}
	body := string(page.Body)
	if !strings.Contains(body, "<strong>alice</strong>: &lt;script&gt;x&lt;/script&gt; <strong>hi</strong>") || strings.Contains(body, "<script>") {
		t.Errorf("wall page = %s", body)
	}
}

func TestFind(t *testing.T) {
	f := setup(t)
	carl := f.User("Carlos")
	for _, u := range []int64{f.alice, f.bob, carl} {
		f.p.Set(f.Ctx, u, "hello")
	}
	tests := []struct {
		query string
		want  []string
		err   error
	}{
		{"b", []string{"bob"}, nil},
		{"  @BO ", []string{"bob"}, nil},
		{"carl", []string{"carlos"}, nil},
		{"zed", nil, nil},
		{"lice", nil, nil}, // prefix, not substring
		{" ", nil, ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			got, err := f.p.Find(f.Ctx, tt.query)
			var names []string
			for _, e := range got {
				names = append(names, e.Username)
			}
			if !errors.Is(err, tt.err) || strings.Join(names, ",") != strings.Join(tt.want, ",") {
				t.Errorf("Find(%q) = %v, %v; want %v, %v", tt.query, names, err, tt.want, tt.err)
			}
		})
	}
}

func TestModeratorRemovesBySearch(t *testing.T) {
	f := setup(t)
	f.p.Set(f.Ctx, f.alice, "alice's line")
	f.p.Set(f.Ctx, f.bob, "bob's line")
	// Show the wall, Remove a member's line (3 of: Write, Find, Remove,
	// Show again, Back), search "bo", pick the match (1), Yes (2), show the
	// wall again, Back (5).
	s := f.Session(f.mod, strings.Join([]string{"", "3", "bo", "1", "2", "", "5"}, "\r")+"\r")
	if err := f.p.run(f.Ctx, s); err != nil {
		t.Fatalf("run: %v\n%s", err, s.Out)
	}
	if _, ok, _ := f.p.Mine(f.Ctx, f.bob); ok {
		t.Errorf("bob's line not removed:\n%s", s.Out)
	}
	if _, ok, _ := f.p.Mine(f.Ctx, f.alice); !ok {
		t.Error("alice's line removed too")
	}
	if strings.Contains(s.Out.String(), "1. alice") {
		t.Error("search listed a member who does not match")
	}
}

func TestSetAccess(t *testing.T) {
	f := setup(t)
	memberG, _ := f.Perms.GroupByName(f.Ctx, perm.GroupMember)
	modG, _ := f.Perms.GroupByName(f.Ctx, perm.GroupModerator)
	adminG, _ := f.Perms.GroupByName(f.Ctx, perm.GroupAdmin)

	a, err := f.p.Access(f.Ctx)
	if err != nil || !a.Write[memberG.ID] || !a.Write[modG.ID] || a.Moderate[memberG.ID] || !a.Moderate[modG.ID] {
		t.Fatalf("default access = %+v, %v", a, err)
	}
	for _, g := range a.Groups {
		if g.ID == adminG.ID {
			t.Error("the admin group is offered, but administrators can always do both")
		}
	}

	if err := f.p.SetAccess(f.Ctx, f.mod, nil, nil); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("moderator changing access err = %v, want forbidden (administrators only)", err)
	}
	if err := f.p.SetAccess(f.Ctx, f.Admin, []int64{adminG.ID}, nil); !errors.Is(err, ErrInvalid) {
		t.Errorf("choosing the admin group err = %v, want ErrInvalid", err)
	}

	// Only moderators may write; members may remove any line.
	if err := f.p.SetAccess(f.Ctx, f.Admin, []int64{modG.ID}, []int64{memberG.ID}); err != nil {
		t.Fatal(err)
	}
	if err := f.p.Set(f.Ctx, f.alice, "hi"); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member writing after access change err = %v", err)
	}
	if err := f.p.Set(f.Ctx, f.mod, "mod line"); err != nil {
		t.Errorf("moderator writing: %v", err)
	}
	if err := f.p.Remove(f.Ctx, f.alice, f.mod); err != nil {
		t.Errorf("member removing with wall.moderate: %v", err)
	}
	if err := f.p.Set(f.Ctx, f.mod, "again"); err != nil {
		t.Fatal(err)
	}
	if err := f.p.Remove(f.Ctx, f.bob, f.Admin); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v; members now moderate, so a missing line is just not found", err)
	}
	if ok, _ := f.Perms.Has(f.Ctx, f.mod, PermModerate); ok {
		t.Error("moderators kept wall.moderate after it was unticked")
	}
	if ok, _ := f.Perms.Has(f.Ctx, f.Admin, PermWrite); !ok {
		t.Error("administrator lost the ability to write")
	}
	if a, _ := f.p.Access(f.Ctx); a.Write[memberG.ID] || !a.Moderate[memberG.ID] {
		t.Errorf("access after change = %+v", a)
	}
}

func TestAccessFormTUI(t *testing.T) {
	f := setup(t)
	memberG, _ := f.Perms.GroupByName(f.Ctx, perm.GroupMember)
	modG, _ := f.Perms.GroupByName(f.Ctx, perm.GroupModerator)
	// Administrator: show the (empty) wall, Choose who can write and
	// moderate (2 of: Write, Choose, Show again, Back), write: moderator
	// (2), moderate: member (1), dismiss "Saved.", show the wall, Back (4).
	s := f.Session(f.Admin, strings.Join([]string{"", "2", "2", "1", "", "", "4"}, "\r")+"\r")
	if err := f.p.run(f.Ctx, s); err != nil {
		t.Fatalf("run: %v\n%s", err, s.Out)
	}
	a, _ := f.p.Access(f.Ctx)
	if a.Write[memberG.ID] || !a.Write[modG.ID] || !a.Moderate[memberG.ID] || a.Moderate[modG.ID] {
		t.Errorf("access = write %v moderate %v\n%s", a.Write, a.Moderate, s.Out)
	}
	for _, want := range []string{"1. member", "2. moderator", "(currently selected)", "Saved."} {
		if !strings.Contains(s.Out.String(), want) {
			t.Errorf("output missing %q", want)
		}
	}
}
