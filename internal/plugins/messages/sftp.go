package messages

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/sftpd"
	"go.privatebychoice.com/shellshawk/internal/tui/term"
)

// mailFS serves a member's own mail read-only over SFTP:
//
//	/messages/inbox/20261116-140300-42-meeting-notes.md
//	/messages/sent/…
//
// Reading a file over SFTP does not mark the message as read.
type mailFS struct{ p *Plugin }

var slugUnsafe = regexp.MustCompile(`[^a-z0-9]+`)

// fileName is "<YYYYMMDD-HHMMSS>-<id>-<subject slug>.md".
func fileName(m Summary) string {
	slug := strings.Trim(slugUnsafe.ReplaceAllString(strings.ToLower(m.Subject), "-"), "-")
	if len(slug) > 40 {
		slug = strings.Trim(slug[:40], "-")
	}
	if slug == "" {
		slug = "message"
	}
	return fmt.Sprintf("%s-%d-%s.md", m.CreatedAt.UTC().Format("20060102-150405"), m.ID, slug)
}

// idFromName extracts the message ID from a file name.
func idFromName(name string) (int64, bool) {
	parts := strings.SplitN(strings.TrimSuffix(name, ".md"), "-", 4)
	if len(parts) < 3 || !strings.HasSuffix(name, ".md") {
		return 0, false
	}
	id, err := strconv.ParseInt(parts[2], 10, 64)
	return id, err == nil
}

func (f *mailFS) List(ctx context.Context, u sftpd.User, dir []string) ([]sftpd.Entry, error) {
	switch {
	case len(dir) == 0:
		return []sftpd.Entry{{Name: Inbox, Dir: true}, {Name: Sent, Dir: true}}, nil
	case len(dir) == 1 && (dir[0] == Inbox || dir[0] == Sent):
		list, err := f.p.List(ctx, u.ID, dir[0])
		if err != nil {
			return nil, err
		}
		out := make([]sftpd.Entry, 0, len(list))
		for _, m := range list {
			out = append(out, sftpd.Entry{Name: fileName(m), ModTime: m.CreatedAt})
		}
		return out, nil
	}
	return nil, sftpd.ErrNotExist
}

func (f *mailFS) Read(ctx context.Context, u sftpd.User, file []string) ([]byte, time.Time, error) {
	if len(file) != 2 || (file[0] != Inbox && file[0] != Sent) {
		return nil, time.Time{}, sftpd.ErrNotExist
	}
	id, ok := idFromName(file[1])
	if !ok {
		return nil, time.Time{}, sftpd.ErrNotExist
	}
	// Only files that appear in the listing can be read, so a guessed ID
	// in the wrong folder (or someone else's message) is not found.
	list, err := f.p.List(ctx, u.ID, file[0])
	if err != nil {
		return nil, time.Time{}, err
	}
	for _, m := range list {
		if m.ID != id || fileName(m) != file[1] {
			continue
		}
		body, err := f.body(ctx, id)
		if err != nil {
			return nil, time.Time{}, err
		}
		to, err := f.p.recipients(ctx, id)
		if err != nil {
			return nil, time.Time{}, err
		}
		doc := fmt.Sprintf("---\nfrom: %s\nto: %s\ndate: %s\nsubject: %q\n---\n\n%s\n",
			m.From, strings.Join(to, ", "), m.CreatedAt.UTC().Format(time.RFC3339), m.Subject, body)
		// Checked when sent; cleaned again on the way out because members
		// open the file in a terminal.
		return []byte(term.Sanitize(doc, true)), m.CreatedAt, nil
	}
	return nil, time.Time{}, sftpd.ErrNotExist
}

func (f *mailFS) body(ctx context.Context, id int64) (string, error) {
	var b string
	err := f.p.h.DB.QueryRowContext(ctx, `SELECT body FROM messages_messages WHERE id = ?`, id).Scan(&b)
	return b, err
}
