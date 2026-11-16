package conferences

import (
	"context"

	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// Placeholders used when a member's content is removed at erasure.
const (
	RemovedBody  = "*[removed by author]*"
	RemovedTitle = "Thread by a former member"
)

// export returns every post the member wrote.
func (p *Plugin) export(ctx context.Context, user int64) ([]export.File, error) {
	rows, err := p.h.DB.QueryContext(ctx, `SELECT a.slug, c.slug, t.title, po.body, po.created_at, po.edited_at
		FROM conferences_posts po JOIN conferences_threads t ON t.id = po.thread_id
		JOIN conferences_conferences c ON c.id = t.conference_id JOIN conferences_areas a ON a.id = c.area_id
		WHERE po.author_id = ? ORDER BY po.created_at`, user)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type postOut struct {
		Area       string  `json:"area"`
		Conference string  `json:"conference"`
		Thread     string  `json:"thread"`
		Body       string  `json:"body"`
		Date       string  `json:"date"`
		Edited     *string `json:"edited"`
	}
	var out []postOut
	for rows.Next() {
		var o postOut
		if err := rows.Scan(&o.Area, &o.Conference, &o.Thread, &o.Body, &o.Date, &o.Edited); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	f, err := export.JSON("posts.json", out)
	return []export.File{f}, err
}

// erase blanks the member's posts and thread titles if they asked for their
// content to be deleted. Posts are blanked rather than removed so other
// members' replies keep their place in the thread. Otherwise the posts stay,
// credited to the anonymous tombstone name.
func (p *Plugin) erase(ctx context.Context, e events.Event) error {
	if !e.DeleteContent {
		return nil
	}
	now := store.FormatTime(p.now())
	if _, err := p.h.DB.ExecContext(ctx, `UPDATE conferences_posts SET body = ?, edited_at = ? WHERE author_id = ?`, RemovedBody, now, e.UserID); err != nil {
		return err
	}
	_, err := p.h.DB.ExecContext(ctx, `UPDATE conferences_threads SET title = ? WHERE author_id = ?`, RemovedTitle, e.UserID)
	return err
}
