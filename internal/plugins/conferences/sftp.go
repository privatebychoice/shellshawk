package conferences

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/sftpd"
)

// threadFS serves whole threads read-only over SFTP:
//
//	/conferences/<area>/<conference>/<YYYYMMDD>-<thread id>-<title slug>.md
//
// The thread ID keeps names unique when two threads share a date and title.
// Only conferences the member can read are listed.
type threadFS struct{ p *Plugin }

var slugUnsafe = regexp.MustCompile(`[^a-z0-9]+`)

func threadFile(t Thread) string {
	slug := strings.Trim(slugUnsafe.ReplaceAllString(strings.ToLower(t.Title), "-"), "-")
	if len(slug) > 50 {
		slug = strings.Trim(slug[:50], "-")
	}
	if slug == "" {
		slug = "thread"
	}
	return fmt.Sprintf("%s-%d-%s.md", t.CreatedAt.UTC().Format("20060102"), t.ID, slug)
}

func (f *threadFS) areaBySlug(ctx context.Context, slug string) (Area, bool, error) {
	areas, err := f.p.Areas(ctx)
	if err != nil {
		return Area{}, false, err
	}
	for _, a := range areas {
		if a.Slug == slug {
			return a, true, nil
		}
	}
	return Area{}, false, nil
}

func (f *threadFS) conf(ctx context.Context, u sftpd.User, areaSlug, confSlug string) (Conference, error) {
	a, ok, err := f.areaBySlug(ctx, areaSlug)
	if err != nil || !ok {
		return Conference{}, errOr(err, sftpd.ErrNotExist)
	}
	confs, err := f.p.Conferences(ctx, u.ID, a.ID)
	if err != nil {
		return Conference{}, err
	}
	for _, c := range confs {
		if c.Slug == confSlug {
			return c, nil
		}
	}
	return Conference{}, sftpd.ErrNotExist
}

func errOr(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}

func (f *threadFS) List(ctx context.Context, u sftpd.User, dir []string) ([]sftpd.Entry, error) {
	switch len(dir) {
	case 0:
		areas, err := f.p.Areas(ctx)
		if err != nil {
			return nil, err
		}
		var out []sftpd.Entry
		for _, a := range areas {
			confs, err := f.p.Conferences(ctx, u.ID, a.ID)
			if err != nil {
				return nil, err
			}
			if len(confs) > 0 {
				out = append(out, sftpd.Entry{Name: a.Slug, Dir: true})
			}
		}
		return out, nil
	case 1:
		a, ok, err := f.areaBySlug(ctx, dir[0])
		if err != nil || !ok {
			return nil, errOr(err, sftpd.ErrNotExist)
		}
		confs, err := f.p.Conferences(ctx, u.ID, a.ID)
		if err != nil {
			return nil, err
		}
		if len(confs) == 0 {
			return nil, sftpd.ErrNotExist
		}
		var out []sftpd.Entry
		for _, c := range confs {
			out = append(out, sftpd.Entry{Name: c.Slug, Dir: true})
		}
		return out, nil
	case 2:
		c, err := f.conf(ctx, u, dir[0], dir[1])
		if err != nil {
			return nil, err
		}
		threads, err := f.p.Threads(ctx, u.ID, c.ID)
		if err != nil {
			return nil, err
		}
		var out []sftpd.Entry
		for _, t := range threads {
			out = append(out, sftpd.Entry{Name: threadFile(t), ModTime: t.LastPostAt})
		}
		return out, nil
	}
	return nil, sftpd.ErrNotExist
}

func (f *threadFS) Read(ctx context.Context, u sftpd.User, file []string) ([]byte, time.Time, error) {
	if len(file) != 3 {
		return nil, time.Time{}, sftpd.ErrNotExist
	}
	c, err := f.conf(ctx, u, file[0], file[1])
	if err != nil {
		return nil, time.Time{}, err
	}
	parts := strings.SplitN(file[2], "-", 3)
	if len(parts) < 3 {
		return nil, time.Time{}, sftpd.ErrNotExist
	}
	id, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return nil, time.Time{}, sftpd.ErrNotExist
	}
	t, tc, _, err := f.p.Thread(ctx, u.ID, id)
	if err != nil || tc.ID != c.ID || threadFile(t) != file[2] {
		return nil, time.Time{}, sftpd.ErrNotExist
	}
	posts, err := f.p.Posts(ctx, u.ID, id)
	if err != nil {
		return nil, time.Time{}, err
	}
	doc := fmt.Sprintf("---\ntitle: %q\nconference: %s/%s\nstarted: %s\nposts: %d\n---\n\n# %s\n\n%s",
		t.Title, c.AreaSlug, c.Slug, t.CreatedAt.UTC().Format(time.RFC3339), len(posts), escape(t.Title), f.p.render(t, posts))
	return []byte(doc), t.LastPostAt, nil
}
