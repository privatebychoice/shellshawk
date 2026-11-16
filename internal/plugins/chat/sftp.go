package chat

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/sftpd"
)

// logFS serves chat logs read-only over SFTP:
//
//	/chat/<channel>/<YYYYMMDD>.log
//
// Only channels the member can currently enter, and that are logged, are
// listed.
type logFS struct{ p *Plugin }

const maxLogLines = 100000

func (f *logFS) channel(ctx context.Context, u sftpd.User, name string) (Channel, error) {
	c, err := f.p.ByName(ctx, name)
	if err != nil {
		return Channel{}, sftpd.ErrNotExist
	}
	ok, err := f.p.CanAccess(ctx, u.ID, c)
	if err != nil {
		return Channel{}, err
	}
	if !ok || c.RetentionDays == 0 || c.Name != name {
		return Channel{}, sftpd.ErrNotExist
	}
	return c, nil
}

func (f *logFS) List(ctx context.Context, u sftpd.User, dir []string) ([]sftpd.Entry, error) {
	switch len(dir) {
	case 0:
		chans, err := f.p.Accessible(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		var out []sftpd.Entry
		for _, c := range chans {
			if c.RetentionDays > 0 {
				out = append(out, sftpd.Entry{Name: c.Name, Dir: true})
			}
		}
		return out, nil
	case 1:
		c, err := f.channel(ctx, u, dir[0])
		if err != nil {
			return nil, err
		}
		rows, err := f.p.h.DB.QueryContext(ctx, `SELECT DISTINCT substr(created_at, 1, 10) FROM chat_messages WHERE channel_id = ? ORDER BY 1`, c.ID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []sftpd.Entry
		for rows.Next() {
			var day string
			if err := rows.Scan(&day); err != nil {
				return nil, err
			}
			t, err := time.Parse("2006-01-02", day)
			if err != nil {
				continue
			}
			out = append(out, sftpd.Entry{Name: t.Format("20060102") + ".log", ModTime: t})
		}
		return out, rows.Err()
	}
	return nil, sftpd.ErrNotExist
}

func (f *logFS) Read(ctx context.Context, u sftpd.User, file []string) ([]byte, time.Time, error) {
	if len(file) != 2 || !strings.HasSuffix(file[1], ".log") {
		return nil, time.Time{}, sftpd.ErrNotExist
	}
	c, err := f.channel(ctx, u, file[0])
	if err != nil {
		return nil, time.Time{}, err
	}
	day, err := time.Parse("20060102", strings.TrimSuffix(file[1], ".log"))
	if err != nil {
		return nil, time.Time{}, sftpd.ErrNotExist
	}
	entries, err := f.p.History(ctx, c, maxLogLines, day, day.Add(24*time.Hour))
	if err != nil {
		return nil, time.Time{}, err
	}
	if len(entries) == 0 {
		return nil, time.Time{}, sftpd.ErrNotExist
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# #%s, %s (UTC)\n", c.Name, day.Format("2006-01-02"))
	for _, e := range entries {
		if e.Kind == "event" {
			fmt.Fprintf(&b, "[%s] * %s\n", e.At.UTC().Format("15:04:05"), e.Body)
		} else {
			fmt.Fprintf(&b, "[%s] %s: %s\n", e.At.UTC().Format("15:04:05"), e.Name, e.Body)
		}
	}
	return []byte(b.String()), entries[len(entries)-1].At, nil
}
