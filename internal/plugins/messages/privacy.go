package messages

import (
	"context"

	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
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
// tombstone name (docs/DESIGN.md §5.2).
func (p *Plugin) erase(ctx context.Context, e events.Event) error {
	_, err := p.h.DB.ExecContext(ctx, `DELETE FROM messages_recipients WHERE user_id = ?`, e.UserID)
	return err
}
