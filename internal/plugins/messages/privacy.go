package messages

import (
	"context"
	"database/sql"
	"fmt"

	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// export returns every message the member received (including deleted
// ones) or sent (including ones removed from Sent that a recipient still
// holds), with no listing limit.
func (p *Plugin) export(ctx context.Context, user int64) ([]export.File, error) {
	type msgOut struct {
		Folder  string   `json:"folder"`
		From    string   `json:"from"`
		To      []string `json:"to"`
		Subject string   `json:"subject"`
		Body    string   `json:"body"`
		Date    any      `json:"date"`
		Read    bool     `json:"read"`
	}
	var out []msgOut
	for _, folder := range []string{Inbox, Deleted, Sent} {
		list, err := p.list(ctx, user, folder, -1)
		if err != nil {
			return nil, err
		}
		for _, m := range list {
			var body string
			if err := p.h.DB.QueryRowContext(ctx, `SELECT body FROM messages_messages WHERE id = ?`, m.ID).Scan(&body); err != nil {
				return nil, err
			}
			to, err := p.recipients(ctx, m.ID)
			if err != nil {
				return nil, err
			}
			out = append(out, msgOut{Folder: folder, From: m.From, To: to, Subject: m.Subject, Body: body, Date: m.CreatedAt, Read: m.Read})
		}
	}
	// Messages the member removed from Sent are still held while a
	// recipient keeps them, so they are part of the member's data too.
	removed, err := p.h.DB.QueryContext(ctx, `SELECT id, subject, body, created_at FROM messages_messages
		WHERE sender_id = ? AND sender_deleted_at IS NOT NULL ORDER BY created_at, id`, user)
	if err != nil {
		return nil, fmt.Errorf("messages: export removed: %w", err)
	}
	type held struct {
		id                     int64
		subject, body, created string
	}
	var list []held
	for removed.Next() {
		var h held
		if err := removed.Scan(&h.id, &h.subject, &h.body, &h.created); err != nil {
			removed.Close()
			return nil, err
		}
		list = append(list, h)
	}
	removed.Close()
	if err := removed.Err(); err != nil {
		return nil, err
	}
	me, err := p.h.Auth.UserByID(ctx, user)
	if err != nil {
		return nil, err
	}
	for _, h := range list {
		to, err := p.recipients(ctx, h.id)
		if err != nil {
			return nil, err
		}
		out = append(out, msgOut{Folder: "removed from sent", From: me.Username, To: to, Subject: h.subject, Body: h.body, Date: h.created, Read: true})
	}
	f, err := export.JSON("messages.json", out)
	return []export.File{f}, err
}

// erase deletes the member's copies of messages they received. Messages
// they sent stay in the recipients' mailboxes, credited to the anonymous
// tombstone name (docs/DESIGN.md §5.2); the member's Sent copies go, so
// messages nobody else holds (such as notes to self) are deleted now, and
// the rest once their last recipient removes them.
func (p *Plugin) erase(ctx context.Context, e events.Event) error {
	return store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM messages_recipients WHERE user_id = ?`, e.UserID); err != nil {
			return fmt.Errorf("messages: erase received: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE messages_messages SET sender_deleted_at = COALESCE(sender_deleted_at, ?) WHERE sender_id = ?`,
			store.FormatTime(p.now()), e.UserID); err != nil {
			return fmt.Errorf("messages: erase sent: %w", err)
		}
		n, err := removeUnheld(ctx, tx)
		if err != nil {
			return err
		}
		p.h.Log.Info("erased messages", "user_id", e.UserID, "messages_removed", n)
		return nil
	})
}
