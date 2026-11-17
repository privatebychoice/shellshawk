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
// ones) or sent.
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
		list, err := p.List(ctx, user, folder)
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
	f, err := export.JSON("messages.json", out)
	return []export.File{f}, err
}

// erase deletes the member's copies of messages they received. Messages
// they sent stay in the recipients' mailboxes, credited to the anonymous
// tombstone name (docs/DESIGN.md §5.2); sent messages nobody else holds
// any more (such as notes to self) are deleted.
func (p *Plugin) erase(ctx context.Context, e events.Event) error {
	return store.WithTx(ctx, p.h.DB, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM messages_recipients WHERE user_id = ?`, e.UserID); err != nil {
			return fmt.Errorf("messages: erase received: %w", err)
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM messages_messages WHERE sender_id = ?
			AND NOT EXISTS (SELECT 1 FROM messages_recipients r WHERE r.message_id = messages_messages.id)`, e.UserID)
		if err != nil {
			return fmt.Errorf("messages: erase unreceived: %w", err)
		}
		n, _ := res.RowsAffected()
		p.h.Log.Info("erased messages", "user_id", e.UserID, "sent_without_recipients_deleted", n)
		return nil
	})
}
