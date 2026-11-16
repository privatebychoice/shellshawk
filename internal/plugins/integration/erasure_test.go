// Package integration tests behaviour that spans every core plugin.
package integration

import (
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/chat"
	"go.privatebychoice.com/shellshawk/internal/plugins/conferences"
	"go.privatebychoice.com/shellshawk/internal/plugins/contacts"
	"go.privatebychoice.com/shellshawk/internal/plugins/messages"
	"go.privatebychoice.com/shellshawk/internal/plugins/plugintest"
	"go.privatebychoice.com/shellshawk/internal/plugins/polls"
	"go.privatebychoice.com/shellshawk/internal/plugins/userlist"
	"go.privatebychoice.com/shellshawk/internal/privacy"
)

type world struct {
	*plugintest.Env
	c    *contacts.Plugin
	m    *messages.Plugin
	pl   *polls.Plugin
	ch   *chat.Plugin
	conf *conferences.Plugin
}

func newWorld(t *testing.T) *world {
	c := contacts.New()
	m := messages.New(c)
	pl, ch := polls.New(), chat.New()
	conf := conferences.New(pl, ch)
	e := plugintest.New(t, []plugin.Plugin{c, m, pl, userlist.New(c, m), ch, conf}...)
	return &world{Env: e, c: c, m: m, pl: pl, ch: ch, conf: conf}
}

func (w *world) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := w.DB.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestErasureAcrossPlugins(t *testing.T) {
	for _, deleteContent := range []bool{true, false} {
		name := map[bool]string{true: "delete content", false: "keep content"}[deleteContent]
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			alice, bob := w.User("alice"), w.User("bob")
			w.Visibility(bob, privacy.Messages, privacy.Public)

			// alice's footprint in every plugin.
			w.c.Add(w.Ctx, alice, "bob", "")
			w.c.Add(w.Ctx, bob, "alice", "")
			w.m.Send(w.Ctx, alice, messages.Draft{To: "bob", Subject: "hi", Body: "from alice"})
			areas, _ := w.conf.Areas(w.Ctx)
			confs, _ := w.conf.Conferences(w.Ctx, alice, areas[0].ID)
			tid, _, _ := w.conf.StartThread(w.Ctx, alice, confs[0].ID, "Alice's thread", "alice's post")
			w.conf.Reply(w.Ctx, bob, tid, "bob's reply")
			poll, _ := w.pl.Create(w.Ctx, polls.Spec{Question: "Q?", Options: []string{"a", "b"}, CreatorID: bob})
			p, _ := w.pl.Get(w.Ctx, alice, poll)
			w.pl.Vote(w.Ctx, alice, poll, []int64{p.Options[0].ID})
			lobby, _ := w.ch.ByName(w.Ctx, "lobby")
			w.DB.Exec(`INSERT INTO chat_messages (channel_id, user_id, kind, body, created_at) VALUES (?, ?, 'message', 'alice says hi', strftime('%Y-%m-%dT%H:%M:%SZ','now'))`, lobby.ID, alice)

			// The export covers every plugin before erasure.
			srcs := append(w.Registry.ExportSources(), w.Privacy.ExportSource())
			var all strings.Builder
			for _, src := range srcs {
				files, err := src.Export(w.Ctx, alice)
				if err != nil {
					t.Fatalf("export %s: %v", src.Name, err)
				}
				for _, f := range files {
					all.Write(f.Data)
				}
			}
			for _, want := range []string{"bob", "from alice", "alice's post", `"choice": "a"`, "alice says hi", `"username": "alice"`} {
				if !strings.Contains(all.String(), want) {
					t.Errorf("export missing %q", want)
				}
			}

			now := privacy.NewService(w.DB, w.Auth, w.Perms, 0, nil, w.Log)
			if _, err := now.RequestErasure(w.Ctx, alice, deleteContent); err != nil {
				t.Fatal(err)
			}
			if n, err := now.RunDue(w.Ctx, w.Events); err != nil || n != 1 {
				t.Fatalf("RunDue = %d, %v", n, err)
			}

			// Always: contacts both ways gone, vote unlinked but counted,
			// sent message kept for bob, no keys or profile.
			if n := w.count(t, `SELECT count(*) FROM contacts_entries WHERE owner_id = ? OR contact_id = ?`, alice, alice); n != 0 {
				t.Errorf("contacts left: %d", n)
			}
			if friend, _ := w.c.IsFriend(w.Ctx, bob, alice); friend {
				t.Error("still a friend")
			}
			if n := w.count(t, `SELECT count(*) FROM polls_votes WHERE user_id = ?`, alice); n != 0 {
				t.Error("vote still linked")
			}
			if p, _ := w.pl.Get(w.Ctx, bob, poll); p.Options[0].Votes != 1 {
				t.Error("vote total lost")
			}
			if inbox, _ := w.m.List(w.Ctx, bob, messages.Inbox); len(inbox) != 1 || !strings.HasPrefix(inbox[0].From, "former-") {
				t.Errorf("bob's message = %+v", inbox)
			}
			posts, _ := w.conf.Posts(w.Ctx, bob, tid)
			chatLines := w.count(t, `SELECT count(*) FROM chat_messages WHERE user_id = ?`, alice)

			if deleteContent {
				if posts[0].Body != conferences.RemovedBody || posts[1].Body != "bob's reply" {
					t.Errorf("posts = %q / %q (alice's blanked, bob's kept)", posts[0].Body, posts[1].Body)
				}
				if th, _, _, _ := w.conf.Thread(w.Ctx, bob, tid); th.Title != conferences.RemovedTitle {
					t.Errorf("thread title = %q", th.Title)
				}
				if chatLines != 0 {
					t.Error("chat lines kept despite delete content")
				}
			} else {
				if posts[0].Body != "alice's post" || !strings.HasPrefix(posts[0].Author, "former-") {
					t.Errorf("kept post = %+v (content kept, author anonymised)", posts[0])
				}
				if chatLines != 1 {
					t.Error("chat lines deleted despite keep content")
				}
			}
		})
	}
}
