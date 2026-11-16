package chat

import (
	"context"

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
// credited to the anonymous tombstone name.
func (p *Plugin) erase(ctx context.Context, e events.Event) error {
	if _, err := p.h.DB.ExecContext(ctx, `DELETE FROM chat_invites WHERE user_id = ?`, e.UserID); err != nil {
		return err
	}
	if e.DeleteContent {
		if _, err := p.h.DB.ExecContext(ctx, `DELETE FROM chat_messages WHERE user_id = ?`, e.UserID); err != nil {
			return err
		}
	}
	return nil
}
