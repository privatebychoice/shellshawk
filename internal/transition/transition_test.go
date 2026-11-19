package transition

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/store"
)

const admin, member = 1, 2

func setup(t *testing.T) (*Service, *sql.DB, context.Context) {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "t.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, q := range []string{
		`INSERT INTO users (id, username, password_hash, status, created_at) VALUES (1, 'a1', 'x', 'active', '2026-01-01T00:00:00Z'), (2, 'm1', 'x', 'active', '2026-01-01T00:00:00Z')`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT 1, id FROM access_groups WHERE name = 'admin'`,
		`INSERT INTO user_access_groups (user_id, group_id) SELECT 2, id FROM access_groups WHERE name = 'member'`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return NewService(db, nil, log), db, ctx
}

func known(target string) bool { return target == "core:settings" || target == "notes:main" }

func TestClean(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
		err  bool
	}{
		{"plain text kept", "  /\\_/\\\n ( o.o )", "  /\\_/\\\n ( o.o )", false},
		{"CRLF and trailing space", "ab  \r\ncd\r\n\r\n", "ab\ncd", false},
		{"leading and trailing blank lines", "\n\n  x\n\n", "  x", false},
		{"tabs expand to 8 columns", "a\tb\n\tc", "a       b\n        c", false},
		{"ANSI colours removed", "\x1b[1;31mred\x1b[0m \x1b[2Jtext", "red text", false},
		{"other controls removed", "a\x07b\x00c", "abc", false},
		{"bidi override removed", "a‮b", "ab", false},
		{"UTF-8 art kept", "╔══╗\n║▓▓║\n╚══╝", "╔══╗\n║▓▓║\n╚══╝", false},
		{"CP437 decoded", "\xc9\xcd\xbb\n\xb0\xb1\xb2\xdb", "╔═╗\n░▒▓█", false},
		{"SAUCE record dropped", "art\x1aSAUCE00 title", "art", false},
		{"only whitespace", " \n\t\n", "", true},
		{"only escape codes", "\x1b[0m\x1b[2J", "", true},
		{"too big", strings.Repeat("x", MaxFileBytes+1), "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Clean([]byte(tt.in))
			if (err != nil) != tt.err {
				t.Fatalf("err = %v", err)
			}
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Errorf("err = %v, want ErrInvalid", err)
			}
			if got != tt.want {
				t.Errorf("Clean = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestASCII(t *testing.T) {
	tests := []struct{ in, want string }{
		{"plain", "plain"},
		{"╔══╗\n║▓▓║\n╚══╝", "+--+\n|##|\n+--+"},
		{"┌─┬─┐│", "+-+-+|"},
		{"café · ☺", "caf? . ?"},
	}
	for _, tt := range tests {
		if got := ASCII(tt.in); got != tt.want {
			t.Errorf("ASCII(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestReason(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{CheckSlug("X"), "Use 1 to 40 lowercase letters, digits and hyphens, starting with a letter or digit."},
		{ErrExists, "A profile with that name already exists."},
		{fmt.Errorf("%w: at most 50 files in a profile", ErrTooMany), "At most 50 files in a profile."},
		{ErrNotEmpty, "The profile still has files."},
	}
	for _, tt := range tests {
		if got := Reason(tt.err); got != tt.want {
			t.Errorf("Reason(%v) = %q, want %q", tt.err, got, tt.want)
		}
	}
}

func TestNames(t *testing.T) {
	tests := []struct {
		slug, name string
		slugOK     bool
		nameOK     bool
	}{
		{"welcome", "logo.txt", true, true},
		{"enter-2", "A_b-1.ans", true, true},
		{"Welcome", ".hidden", false, false},
		{"-x", "../x", false, false},
		{strings.Repeat("a", MaxSlugLen+1), strings.Repeat("a", MaxNameLen+1), false, false},
		{"a b", "a b", false, false},
	}
	for _, tt := range tests {
		if (CheckSlug(tt.slug) == nil) != tt.slugOK {
			t.Errorf("CheckSlug(%q) ok = %v", tt.slug, !tt.slugOK)
		}
		if (CheckName(tt.name) == nil) != tt.nameOK {
			t.Errorf("CheckName(%q) ok = %v", tt.name, !tt.nameOK)
		}
	}
}

func TestProfilesAndFiles(t *testing.T) {
	s, db, ctx := setup(t)

	if _, err := s.CreateProfile(ctx, member, "welcome"); !errors.Is(err, perm.ErrForbidden) {
		t.Fatalf("member create = %v", err)
	}
	id, err := s.CreateProfile(ctx, admin, "welcome")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateProfile(ctx, admin, "welcome"); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate = %v", err)
	}
	if _, err := s.CreateProfile(ctx, admin, "Bad Name"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad slug = %v", err)
	}
	for _, f := range []struct{ name, body string }{{"a.txt", "AAA"}, {"b.txt", "BBB\r\n"}} {
		if err := s.SaveFile(ctx, admin, id, f.name, []byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveFile(ctx, member, id, "c.txt", []byte("C")); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("member save = %v", err)
	}
	if err := s.SaveFile(ctx, admin, id, "../c", []byte("C")); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad name = %v", err)
	}
	if body, _, err := s.ReadFile(ctx, id, "b.txt"); err != nil || body != "BBB" {
		t.Errorf("ReadFile = %q, %v", body, err)
	}
	files, _ := s.Files(ctx, id)
	if len(files) != 2 || files[0].Name != "a.txt" || files[1].Size != 3 {
		t.Errorf("Files = %+v", files)
	}

	// Single mode needs one of the profile's files.
	if err := s.UpdateProfile(ctx, admin, id, "welcome", ModeSingle, "zzz.txt"); !errors.Is(err, ErrInvalid) {
		t.Errorf("single with a missing file = %v", err)
	}
	if err := s.UpdateProfile(ctx, admin, id, "hello", ModeSingle, "b.txt"); err != nil {
		t.Fatal(err)
	}
	p, _ := s.ProfileByID(ctx, id)
	if p.Slug != "hello" || p.Mode != ModeSingle || p.File != "b.txt" || p.Files != 2 {
		t.Errorf("profile = %+v", p)
	}
	// Deleting the chosen file switches the profile to random.
	if err := s.DeleteFile(ctx, admin, id, "b.txt"); err != nil {
		t.Fatal(err)
	}
	if p, _ = s.ProfileByID(ctx, id); p.Mode != ModeRandom || p.File != "" {
		t.Errorf("after deleting the chosen file = %+v", p)
	}
	if err := s.DeleteFile(ctx, admin, id, "b.txt"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing = %v", err)
	}

	// Uploading creates the profile.
	if err := s.Upload(ctx, admin, "exit-art", "bye.txt", []byte("bye")); err != nil {
		t.Fatal(err)
	}
	up, err := s.ProfileBySlug(ctx, "exit-art")
	if err != nil || up.Files != 1 {
		t.Errorf("uploaded profile = %+v, %v", up, err)
	}
	if err := s.DeleteProfile(ctx, admin, up.ID, true); !errors.Is(err, ErrNotEmpty) {
		t.Errorf("rmdir of a profile with files = %v", err)
	}
	if err := s.DeleteProfile(ctx, admin, up.ID, false); err != nil {
		t.Fatal(err)
	}
	var left int
	db.QueryRow(`SELECT count(*) FROM transition_files WHERE profile_id = ?`, up.ID).Scan(&left)
	if left != 0 {
		t.Errorf("%d files left after deleting the profile", left)
	}

	var audited int
	db.QueryRow(`SELECT count(*) FROM audit_log WHERE action = 'transition.changed'`).Scan(&audited)
	var details []string
	rows, _ := db.Query(`SELECT detail FROM audit_log WHERE action = 'transition.changed' ORDER BY id`)
	for rows.Next() {
		var d string
		rows.Scan(&d)
		details = append(details, d)
	}
	rows.Close()
	want := "created profile welcome|saved file welcome/a.txt|saved file welcome/b.txt|updated profile welcome (now hello, single)|" +
		"deleted file hello/b.txt|uploaded exit-art/bye.txt|deleted profile exit-art"
	if got := strings.Join(details, "|"); got != want {
		t.Errorf("audit details:\n got %s\nwant %s", got, want)
	}
	// create, two saves, update, delete file, upload, delete profile; refusals are not audited.
	if audited != 7 {
		t.Errorf("audit entries = %d, want 7", audited)
	}
}

func TestFileLimit(t *testing.T) {
	s, _, ctx := setup(t)
	id, _ := s.CreateProfile(ctx, admin, "many")
	for i := range MaxFiles {
		if err := s.SaveFile(ctx, admin, id, fmt.Sprintf("f%02d.txt", i), []byte("x")); err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
	}
	if err := s.SaveFile(ctx, admin, id, "one-more", []byte("x")); !errors.Is(err, ErrTooMany) {
		t.Errorf("file over the limit = %v", err)
	}
	files, _ := s.Files(ctx, id)
	if err := s.SaveFile(ctx, admin, id, files[0].Name, []byte("replaced")); err != nil {
		t.Errorf("replacing a file at the limit = %v", err)
	}
}

func TestPick(t *testing.T) {
	s, _, ctx := setup(t)
	next := 0
	s.pick = func(n int) int { return next % n }
	enter, _ := s.CreateProfile(ctx, admin, "enter")
	s.SaveFile(ctx, admin, enter, "one.txt", []byte("ONE"))
	s.SaveFile(ctx, admin, enter, "two.txt", []byte("TWO"))
	exit, _ := s.CreateProfile(ctx, admin, "exit")
	s.SaveFile(ctx, admin, exit, "bye.txt", []byte("BYE"))
	empty, _ := s.CreateProfile(ctx, admin, "empty")

	set := func(target, moment string, c Choice) {
		t.Helper()
		if err := s.SetPoint(ctx, admin, target, moment, c, known); err != nil {
			t.Fatal(err)
		}
	}
	pick := func(target, moment string) string {
		t.Helper()
		text, ok, err := s.Pick(ctx, target, moment)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return "(none)"
		}
		return text
	}

	if got := pick("core:settings", Enter); got != "(none)" {
		t.Errorf("nothing set = %q", got)
	}
	set(DefaultTarget, Enter, Choice{ProfileID: enter})
	set(DefaultTarget, Exit, Choice{ProfileID: exit})
	if got := pick("core:settings", Enter); got != "ONE" {
		t.Errorf("default enter = %q", got)
	}
	next = 1
	if got := pick("core:settings", Enter); got != "TWO" {
		t.Errorf("random pick = %q", got)
	}
	// An item's own setting wins over the default; "none" hides it.
	set("notes:main", Enter, Choice{ProfileID: exit})
	set("notes:main", Exit, Choice{})
	if got := pick("notes:main", Enter); got != "BYE" {
		t.Errorf("item enter = %q", got)
	}
	if got := pick("notes:main", Exit); got != "(none)" {
		t.Errorf("item exit set to none = %q", got)
	}
	if got := pick("core:settings", Exit); got != "BYE" {
		t.Errorf("other item still uses the default = %q", got)
	}
	// Inherit removes the item's own setting.
	set("notes:main", Exit, Choice{Inherit: true})
	if got := pick("notes:main", Exit); got != "BYE" {
		t.Errorf("after inherit = %q", got)
	}
	// Single mode always shows the chosen file.
	if err := s.UpdateProfile(ctx, admin, enter, "enter", ModeSingle, "one.txt"); err != nil {
		t.Fatal(err)
	}
	next = 1
	if got := pick("core:settings", Enter); got != "ONE" {
		t.Errorf("single = %q", got)
	}
	// A profile without files shows nothing.
	set(DefaultTarget, Enter, Choice{ProfileID: empty})
	if got := pick("core:settings", Enter); got != "(none)" {
		t.Errorf("empty profile = %q", got)
	}
	// Deleting a profile drops the points that used it.
	if err := s.DeleteProfile(ctx, admin, exit, false); err != nil {
		t.Fatal(err)
	}
	pts, _ := s.Points(ctx)
	if _, ok := pts[PointKey(DefaultTarget, Exit)]; ok || len(pts) != 1 {
		t.Errorf("points after deleting a profile = %+v", pts)
	}

	tests := []struct {
		name   string
		actor  int64
		target string
		moment string
		c      Choice
		want   error
	}{
		{"member", member, DefaultTarget, Enter, Choice{}, perm.ErrForbidden},
		{"unknown item", admin, "gone:item", Enter, Choice{}, ErrInvalid},
		{"unknown moment", admin, DefaultTarget, "during", Choice{}, ErrInvalid},
		{"unknown profile", admin, DefaultTarget, Enter, Choice{ProfileID: 999}, ErrNotFound},
	}
	for _, tt := range tests {
		if err := s.SetPoint(ctx, tt.actor, tt.target, tt.moment, tt.c, known); !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
}
