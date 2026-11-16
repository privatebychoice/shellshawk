package polls

import (
	"context"

	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
)

// export returns the member's votes and the polls they created.
func (p *Plugin) export(ctx context.Context, user int64) ([]export.File, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT pp.question, o.label, v.created_at FROM polls_votes v
		JOIN polls_options o ON o.id = v.option_id JOIN polls_polls pp ON pp.id = v.poll_id
		WHERE v.user_id = ? ORDER BY v.created_at`, user)
	if err != nil {
		return nil, err
	}
	type voteOut struct {
		Poll   string `json:"poll"`
		Choice string `json:"choice"`
		Date   string `json:"date"`
	}
	var votes []voteOut
	for rows.Next() {
		var v voteOut
		if err := rows.Scan(&v.Poll, &v.Choice, &v.Date); err != nil {
			rows.Close()
			return nil, err
		}
		votes = append(votes, v)
	}
	rows.Close()
	rows, err = p.h.DB.QueryContext(ctx, `SELECT question, created_at FROM polls_polls WHERE creator_id = ? ORDER BY created_at`, user)
	if err != nil {
		return nil, err
	}
	type pollOut struct {
		Question string `json:"question"`
		Created  string `json:"created"`
	}
	var created []pollOut
	for rows.Next() {
		var c pollOut
		if err := rows.Scan(&c.Question, &c.Created); err != nil {
			rows.Close()
			return nil, err
		}
		created = append(created, c)
	}
	rows.Close()
	f, err := export.JSON("polls.json", map[string]any{"votes": votes, "created": created})
	return []export.File{f}, err
}

// erase unlinks the member's votes: totals are kept, but no vote can be
// traced to anyone (docs/DESIGN.md §5.2).
func (p *Plugin) erase(ctx context.Context, e events.Event) error {
	_, err := p.h.DB.ExecContext(ctx, `UPDATE polls_votes SET user_id = NULL WHERE user_id = ?`, e.UserID)
	return err
}
