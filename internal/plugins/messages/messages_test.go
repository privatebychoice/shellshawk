package messages

import (
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/contacts"
	"go.privatebychoice.com/shellshawk/internal/plugins/plugintest"
	"go.privatebychoice.com/shellshawk/internal/privacy"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
)

type fixture struct {
	*plugintest.Env
	c                 *contacts.Plugin
	p                 *Plugin
	alice, bob, carol int64
}

func setup(t *testing.T) *fixture {
	t.Helper()
	c := contacts.New()
	p := New(c)
	e := plugintest.New(t, c, p)
	f := &fixture{Env: e, c: c, p: p, alice: e.User("alice"), bob: e.User("bob"), carol: e.User("carol")}
	// The default lets only friends send messages; these tests are about
	// messaging itself, so everyone accepts messages from anyone.
	for _, u := range []int64{f.alice, f.bob, f.carol} {
		e.Visibility(u, privacy.Messages, privacy.Public)
	}
	return f
}

func TestSend(t *testing.T) {
	f := setup(t)
	f.c.Add(f.Ctx, f.alice, "bob", "")
	f.c.Add(f.Ctx, f.alice, "carol", "")
	g, _ := f.c.CreateGroup(f.Ctx, f.alice, "team")
	f.c.AddToGroup(f.Ctx, f.alice, g, f.bob)
	f.c.AddToGroup(f.Ctx, f.alice, g, f.carol)

	tests := []struct {
		name   string
		d      Draft
		want   error
		wantTo []string
	}{
		{"one recipient", Draft{To: "bob", Subject: "Hi", Body: "Hello"}, nil, []string{"bob"}},
		{"names trimmed, @ allowed, dedupe, self dropped", Draft{To: " @Bob , bob, alice", Subject: "Hi", Body: "x"}, nil, []string{"bob"}},
		{"contact group", Draft{ContactGroups: []string{"TEAM"}, Subject: "Hi", Body: "x"}, nil, []string{"bob", "carol"}},
		{"unknown user", Draft{To: "bob, ghost", Subject: "Hi", Body: "x"}, &RecipientError{}, nil},
		{"someone else's group", Draft{ContactGroups: []string{"nope"}, Subject: "Hi", Body: "x"}, &RecipientError{}, nil},
		{"only self", Draft{To: "alice", Subject: "Hi", Body: "x"}, ErrNoneToSend, nil},
		{"empty subject", Draft{To: "bob", Subject: " ", Body: "x"}, ErrInvalid, nil},
		{"escape in subject", Draft{To: "bob", Subject: "Hi\x1b[2J", Body: "x"}, ErrInvalid, nil},
		{"empty body", Draft{To: "bob", Subject: "Hi", Body: "\n\n"}, ErrInvalid, nil},
		{"escape in body", Draft{To: "bob", Subject: "Hi", Body: "a\x1b]0;x\x07"}, ErrInvalid, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := f.p.Send(f.Ctx, f.alice, tt.d)
			var re *RecipientError
			switch {
			case errors.As(tt.want, &re):
				if !errors.As(err, &re) {
					t.Fatalf("err = %v, want RecipientError", err)
				}
				return
			case !errors.Is(err, tt.want):
				t.Fatalf("err = %v, want %v", err, tt.want)
			case err != nil:
				return
			}
			m, err := f.p.Read(f.Ctx, f.alice, id)
			if err != nil || !slices.Equal(m.To, tt.wantTo) || m.From != "alice" {
				t.Errorf("sent message = %+v, %v", m, err)
			}
		})
	}
}

func TestReadDeleteRestoreAndCounts(t *testing.T) {
	f := setup(t)
	id, err := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "Lunch?", Body: "**Noon**"})
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := f.p.Count(f.Ctx, f.bob); c != (Counts{Unread: 1}) {
		t.Errorf("counts before read = %+v", c)
	}
	inbox, _ := f.p.List(f.Ctx, f.bob, Inbox)
	if len(inbox) != 1 || inbox[0].Read || inbox[0].From != "alice" {
		t.Fatalf("inbox = %+v", inbox)
	}
	if _, err := f.p.Read(f.Ctx, f.carol, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("non-recipient read err = %v", err)
	}
	m, err := f.p.Read(f.Ctx, f.bob, id)
	if err != nil || m.Body != "**Noon**" || m.Role != RoleRecipient {
		t.Fatalf("read = %+v, %v", m, err)
	}
	if c, _ := f.p.Count(f.Ctx, f.bob); c != (Counts{Read: 1}) {
		t.Errorf("counts after read = %+v", c)
	}
	if err := f.p.Delete(f.Ctx, f.bob, id); err != nil {
		t.Fatal(err)
	}
	if c, _ := f.p.Count(f.Ctx, f.bob); c != (Counts{Deleted: 1}) {
		t.Errorf("counts after delete = %+v", c)
	}
	if del, _ := f.p.List(f.Ctx, f.bob, Deleted); len(del) != 1 {
		t.Error("deleted folder empty")
	}
	// The sender's copy is unaffected by the recipient deleting theirs.
	if sent, _ := f.p.List(f.Ctx, f.alice, Sent); len(sent) != 1 || sent[0].To[0] != "bob" {
		t.Errorf("sent = %+v", sent)
	}
	if err := f.p.Restore(f.Ctx, f.bob, id); err != nil {
		t.Fatal(err)
	}
	if c, _ := f.p.Count(f.Ctx, f.bob); c != (Counts{Read: 1}) {
		t.Errorf("counts after restore = %+v", c)
	}
	if err := f.p.Delete(f.Ctx, f.alice, id); err != nil {
		t.Fatal(err)
	}
	if sent, _ := f.p.List(f.Ctx, f.alice, Sent); len(sent) != 0 {
		t.Error("sender delete did not remove from Sent")
	}
	if _, err := f.p.Read(f.Ctx, f.alice, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("sender read after delete err = %v", err)
	}
	if _, err := f.p.Read(f.Ctx, f.bob, id); err != nil {
		t.Errorf("recipient lost the message when the sender deleted theirs: %v", err)
	}
}

func TestReplies(t *testing.T) {
	f := setup(t)
	id, _ := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "Q", Body: "?"})
	if _, err := f.p.Send(f.Ctx, f.carol, Draft{To: "alice", Subject: "Re: Q", Body: "x", ParentID: id}); !errors.Is(err, ErrNotFound) {
		t.Errorf("reply to a message carol cannot see err = %v", err)
	}
	rid, err := f.p.Send(f.Ctx, f.bob, Draft{To: "alice", Subject: "Re: Q", Body: "!", ParentID: id})
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := f.p.Read(f.Ctx, f.alice, rid); m.ParentID != id {
		t.Errorf("parent = %d", m.ParentID)
	}
}

func TestLimitsAndPermission(t *testing.T) {
	f := setup(t)
	st := f.Registry.Plugins()[1].Settings
	if errs, err := st.Save(f.Ctx, f.Admin, form.Values{setMaxRecipients: "1", setMaxPerHour: "2", setMaxBody: "100"}); err != nil || errs != nil {
		t.Fatal(errs, err)
	}
	if _, err := f.p.Send(f.Ctx, f.alice, Draft{To: "bob, carol", Subject: "x", Body: "x"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("too many recipients err = %v", err)
	}
	if _, err := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "x", Body: strings.Repeat("y", 101)}); !errors.Is(err, ErrInvalid) {
		t.Errorf("long body err = %v", err)
	}
	for range 2 {
		if _, err := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "x", Body: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "x", Body: "x"}); !errors.Is(err, ErrRateLimit) {
		t.Errorf("rate limit err = %v", err)
	}
	f.p.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "x", Body: "x"}); err != nil {
		t.Errorf("after an hour: %v", err)
	}

	// Revoking messages.send from members stops sending.
	g, _ := f.Perms.GroupByName(f.Ctx, perm.GroupMember)
	if err := f.Perms.Revoke(f.Ctx, f.Admin, g.ID, PermSend); err != nil {
		t.Fatal(err)
	}
	if _, err := f.p.Send(f.Ctx, f.bob, Draft{To: "alice", Subject: "x", Body: "x"}); !errors.Is(err, perm.ErrForbidden) {
		t.Errorf("send without permission err = %v", err)
	}
}

func TestSFTP(t *testing.T) {
	f := setup(t)
	id, _ := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "Meeting notes: Q4!", Body: "Agenda"})
	fs := &mailFS{p: f.p}
	bob := sftpd.User{ID: f.bob, Name: "bob"}

	top, _ := fs.List(f.Ctx, bob, nil)
	if len(top) != 2 || !top[0].Dir {
		t.Errorf("top = %+v", top)
	}
	inbox, err := fs.List(f.Ctx, bob, []string{Inbox})
	if err != nil || len(inbox) != 1 || !strings.HasSuffix(inbox[0].Name, "-meeting-notes-q4.md") {
		t.Fatalf("inbox = %+v, %v", inbox, err)
	}
	data, _, err := fs.Read(f.Ctx, bob, []string{Inbox, inbox[0].Name})
	if err != nil || !strings.Contains(string(data), "from: alice") || !strings.HasSuffix(string(data), "Agenda\n") {
		t.Errorf("file = %q, %v", data, err)
	}
	if c, _ := f.p.Count(f.Ctx, f.bob); c.Unread != 1 {
		t.Error("reading over SFTP marked the message read")
	}
	carol := sftpd.User{ID: f.carol, Name: "carol"}
	if _, _, err := fs.Read(f.Ctx, carol, []string{Inbox, inbox[0].Name}); !errors.Is(err, sftpd.ErrNotExist) {
		t.Errorf("another member reading bob's file err = %v", err)
	}
	if _, _, err := fs.Read(f.Ctx, bob, []string{Sent, inbox[0].Name}); !errors.Is(err, sftpd.ErrNotExist) {
		t.Errorf("inbox file read via sent err = %v", err)
	}
	if got, ok := idFromName(inbox[0].Name); !ok || got != id {
		t.Errorf("idFromName = %d, %v", got, ok)
	}
}

func TestMessagePrivacy(t *testing.T) {
	f := setup(t)
	dave := f.User("dave") // default: friends only
	if _, err := f.p.Send(f.Ctx, f.alice, Draft{To: "dave", Subject: "Hi", Body: "x"}); err == nil {
		t.Fatal("stranger messaged a friends-only member")
	} else {
		var re *RecipientError
		if !errors.As(err, &re) || len(re.Refused) != 1 || re.Refused[0] != "dave" {
			t.Errorf("err = %v, want dave refused", err)
		}
	}
	f.c.Add(f.Ctx, f.alice, "dave", "")
	f.c.Add(f.Ctx, dave, "alice", "")
	if _, err := f.p.Send(f.Ctx, f.alice, Draft{To: "dave", Subject: "Hi", Body: "x"}); err != nil {
		t.Errorf("friend refused: %v", err)
	}
	f.Visibility(dave, privacy.Messages, privacy.NoOne)
	if _, err := f.p.Send(f.Ctx, f.alice, Draft{To: "dave", Subject: "Hi", Body: "x"}); err == nil {
		t.Error("No one setting ignored")
	}
}

func TestEraseAndExport(t *testing.T) {
	f := setup(t)
	f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "From alice", Body: "kept for bob"})
	f.p.Send(f.Ctx, f.bob, Draft{To: "alice", Subject: "To alice", Body: "gone with alice"})

	files, err := f.p.export(f.Ctx, f.alice)
	if err != nil || len(files) != 1 || !strings.Contains(string(files[0].Data), "gone with alice") || !strings.Contains(string(files[0].Data), "kept for bob") {
		t.Fatalf("export = %v, %v", files, err)
	}
	now := privacy.NewService(f.DB, f.Auth, f.Perms, 0, nil, f.Log) // no grace period: erase at once
	if _, err := now.RequestErasure(f.Ctx, f.alice, false); err != nil {
		t.Fatal(err)
	}
	if n, err := now.RunDue(f.Ctx, f.Events); err != nil || n != 1 {
		t.Fatalf("RunDue = %d, %v", n, err)
	}
	inbox, _ := f.p.List(f.Ctx, f.bob, Inbox)
	if len(inbox) != 1 || !strings.HasPrefix(inbox[0].From, "former-") {
		t.Errorf("bob's inbox after erasure = %+v (body kept, sender anonymised)", inbox)
	}
	var left int
	f.DB.QueryRow(`SELECT count(*) FROM messages_recipients WHERE user_id = ?`, f.alice).Scan(&left)
	if left != 0 {
		t.Error("erased member's received messages kept")
	}
}

func TestWebPages(t *testing.T) {
	f := setup(t)
	id, _ := f.p.Send(f.Ctx, f.alice, Draft{To: "bob", Subject: "Hi <b>", Body: "*there*"})
	inbox, err := f.WebGet(f.p, "/", nil, f.bob)
	if err != nil || !strings.Contains(string(inbox.Body), "New: ") || !strings.Contains(string(inbox.Body), "Hi &lt;b&gt;") {
		t.Errorf("inbox = %s, %v", inbox.Body, err)
	}
	msg, err := f.WebGet(f.p, "/m/{id}", map[string]string{"id": strconv.FormatInt(id, 10)}, f.bob)
	if err != nil || !strings.Contains(string(msg.Body), "<em>there</em>") {
		t.Errorf("message = %s, %v", msg.Body, err)
	}
	if c, _ := f.p.Count(f.Ctx, f.bob); c.Unread != 0 {
		t.Error("opening on the web did not mark the message read")
	}
	if _, err := f.WebGet(f.p, "/m/{id}", map[string]string{"id": strconv.FormatInt(id, 10)}, f.carol); !errors.Is(err, plugin.ErrWebNotFound) {
		t.Errorf("someone else's message err = %v", err)
	}
}
