package chat

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"unicode/utf8"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
)

// export returns the member's logged chat lines.
func (p *Plugin) export(ctx context.Context, user int64) ([]export.File, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT c.name, m.kind, m.body, m.created_at FROM chat_messages m
		JOIN chat_channels c ON c.id = m.channel_id WHERE m.user_id = ? ORDER BY m.created_at`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type lineOut struct {
		Channel string `json:"channel"`
		Kind    string `json:"kind"`
		Text    string `json:"text"`
		Date    string `json:"date"`
	}
	var out []lineOut
	for rows.Next() {
		var l lineOut
		if err := rows.Scan(&l.Channel, &l.Kind, &l.Text, &l.Date); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	f, err := export.JSON("chat.json", out)
	return []export.File{f}, err
}

// erase removes the member's invitations and, if they asked for their
// content to be deleted, their logged lines. Otherwise the lines stay,
// credited to the anonymous tombstone name. Either way their username is
// replaced with the tombstone name where chat wrote it into stored text:
// the names and default topics of their talk chats ("talk-alice-bob",
// "alice and bob") and their logged topic changes ("alice changed the
// topic to: …").
func (p *Plugin) erase(ctx context.Context, e events.Event) error {
	old, err := p.h.Auth.UserByID(ctx, e.UserID)
	if err != nil {
		return err
	}
	tomb := e.Tombstone
	if tomb == "" {
		tomb = auth.TombstonePrefix + "member"
	}
	if err := p.renameTalkChats(ctx, e.UserID, old.Username, tomb); err != nil {
		return err
	}
	if _, err := p.h.DB.ExecContext(ctx, `DELETE FROM chat_invites WHERE user_id = ?`, e.UserID); err != nil {
		return err
	}
	if e.DeleteContent {
		if _, err := p.h.DB.ExecContext(ctx, `DELETE FROM chat_messages WHERE user_id = ?`, e.UserID); err != nil {
			return err
		}
		return nil
	}
	prefix := old.Username + " "
	_, err = p.h.DB.ExecContext(ctx, `UPDATE chat_messages SET body = ? || substr(body, ?)
		WHERE user_id = ? AND kind = 'event' AND substr(body, 1, ?) = ?`,
		tomb+" ", utf8.RuneCountInString(prefix)+1, e.UserID, utf8.RuneCountInString(prefix), prefix)
	return err
}

// renameTalkChats renames the talk chats between user and someone else
// (private chats named "talk-…" with exactly the two of them, as paging
// makes them) to use tomb instead of their name, and their topic if it is
// still the default "a and b".
func (p *Plugin) renameTalkChats(ctx context.Context, user int64, name, tomb string) error {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT c.id, c.topic, CASE WHEN c.creator_id = ? THEN i.user_id ELSE c.creator_id END
		FROM chat_channels c JOIN chat_invites i ON i.channel_id = c.id
		WHERE c.kind = 'adhoc' AND c.name LIKE ? ESCAPE '\' AND (c.creator_id = ? OR i.user_id = ?)
			AND (SELECT count(*) FROM chat_invites j WHERE j.channel_id = c.id) = 1`, user, talkPrefix+"%", user, user)
	if err != nil {
		return fmt.Errorf("chat: find talk chats: %w", err)
	}
	type talk struct {
		id    int64
		topic string
		other int64
	}
	var list []talk
	for rows.Next() {
		var t talk
		var other sql.NullInt64
		if err := rows.Scan(&t.id, &t.topic, &other); err != nil {
			rows.Close()
			return err
		}
		t.other = other.Int64
		list = append(list, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, t := range list {
		others, err := p.h.Auth.Usernames(ctx, []int64{t.other})
		if err != nil {
			return err
		}
		other := others[t.other]
		if other == "" {
			other = "former"
		}
		topic := t.topic
		switch topic {
		case name + " and " + other:
			topic = tomb + " and " + other
		case other + " and " + name:
			topic = other + " and " + tomb
		}
		base := talkName(tomb, other)
		renamed := false
		for i := 1; i <= 9 && !renamed; i++ {
			newName := base
			if i > 1 {
				newName = base + "-" + strconv.Itoa(i)
			}
			res, err := p.h.DB.ExecContext(ctx, `UPDATE chat_channels SET name = ?, topic = ? WHERE id = ? AND NOT EXISTS (SELECT 1 FROM chat_channels WHERE name = ? AND id <> ?)`,
				newName, topic, t.id, newName, t.id)
			if err != nil {
				return fmt.Errorf("chat: rename talk chat: %w", err)
			}
			n, _ := res.RowsAffected()
			renamed = n == 1
		}
		if !renamed {
			return fmt.Errorf("chat: no free name for talk chat %d", t.id)
		}
	}
	if len(list) > 0 {
		p.h.Log.Info("talk chats renamed for an erased member", "user_id", user, "count", len(list))
	}
	return nil
}
