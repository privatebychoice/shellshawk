package sftpd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/export"
	"go.privatebychoice.com/shellshawk/internal/perm"
)

// MeMount is /me: the member's own data, read-only.
//
//	/me/profile.md            account details in markdown
//	/me/keys.pub              the member's public keys, authorized_keys format
//	/me/export/...            everything stored about the member (right of
//	                          access), produced by core and each plugin
func MeMount(a *auth.Service, p *perm.Service, sources ...export.Source) Mount {
	return Mount{Name: "me", FS: &meFS{auth: a, perms: p, sources: sources}}
}

type meFS struct {
	auth    *auth.Service
	perms   *perm.Service
	sources []export.Source
}

// exportFiles returns the files of one export directory ("" = top level).
func (m *meFS) exportFiles(ctx context.Context, u User, dir string) ([]export.File, error) {
	var out []export.File
	for _, src := range m.sources {
		if src.Name != dir {
			continue
		}
		files, err := src.Export(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if validName(f.Name) {
				out = append(out, f)
			}
		}
	}
	return out, nil
}

func (m *meFS) files(ctx context.Context, u User) (map[string][]byte, error) {
	acct, err := m.auth.UserByID(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	groups, err := m.perms.UserGroups(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	keys, err := m.auth.Keys(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	when := func(t *time.Time) string {
		if t == nil {
			return "never"
		}
		return t.UTC().Format(time.RFC3339)
	}
	var prof strings.Builder
	fmt.Fprintf(&prof, "# %s\n\n", acct.Username)
	fmt.Fprintf(&prof, "- Status: %s\n", acct.Status)
	fmt.Fprintf(&prof, "- Registered: %s\n", when(&acct.CreatedAt))
	fmt.Fprintf(&prof, "- Last login: %s\n", when(acct.LastLoginAt))
	fmt.Fprintf(&prof, "- Groups: %s\n", strings.Join(groups, ", "))
	fmt.Fprintf(&prof, "- SSH keys: %d of %d\n", len(keys), auth.MaxKeysPerUser)

	var pub strings.Builder
	for _, k := range keys {
		pub.WriteString(k.PublicKey)
		if k.Label != "" {
			pub.WriteString(" " + k.Label)
		}
		pub.WriteString("\n")
	}
	return map[string][]byte{"profile.md": []byte(prof.String()), "keys.pub": []byte(pub.String())}, nil
}

// List implements FS.
func (m *meFS) List(ctx context.Context, u User, dir []string) ([]Entry, error) {
	if len(dir) > 0 && dir[0] == "export" {
		return m.listExport(ctx, u, dir[1:])
	}
	if len(dir) != 0 {
		return nil, ErrNotExist
	}
	files, err := m.files(ctx, u)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return []Entry{
		{Name: "export", Dir: true},
		{Name: "keys.pub", Size: int64(len(files["keys.pub"])), ModTime: now},
		{Name: "profile.md", Size: int64(len(files["profile.md"])), ModTime: now},
	}, nil
}

func (m *meFS) listExport(ctx context.Context, u User, dir []string) ([]Entry, error) {
	now := time.Now()
	switch len(dir) {
	case 0:
		files, err := m.exportFiles(ctx, u, "")
		if err != nil {
			return nil, err
		}
		var out []Entry
		for _, f := range files {
			out = append(out, Entry{Name: f.Name, Size: int64(len(f.Data)), ModTime: now})
		}
		for _, src := range m.sources {
			if src.Name != "" && validName(src.Name) {
				out = append(out, Entry{Name: src.Name, Dir: true})
			}
		}
		return out, nil
	case 1:
		for _, src := range m.sources {
			if src.Name == dir[0] && src.Name != "" {
				files, err := m.exportFiles(ctx, u, src.Name)
				if err != nil {
					return nil, err
				}
				var out []Entry
				for _, f := range files {
					out = append(out, Entry{Name: f.Name, Size: int64(len(f.Data)), ModTime: now})
				}
				return out, nil
			}
		}
	}
	return nil, ErrNotExist
}

// Read implements FS.
func (m *meFS) Read(ctx context.Context, u User, file []string) ([]byte, time.Time, error) {
	if len(file) >= 2 && file[0] == "export" {
		dir, name := "", file[len(file)-1]
		if len(file) == 3 {
			dir = file[1]
		} else if len(file) != 2 {
			return nil, time.Time{}, ErrNotExist
		}
		if len(file) == 3 && dir == "" {
			return nil, time.Time{}, ErrNotExist
		}
		files, err := m.exportFiles(ctx, u, dir)
		if err != nil {
			return nil, time.Time{}, err
		}
		for _, f := range files {
			if f.Name == name {
				return f.Data, time.Now(), nil
			}
		}
		return nil, time.Time{}, ErrNotExist
	}
	if len(file) != 1 {
		return nil, time.Time{}, ErrNotExist
	}
	files, err := m.files(ctx, u)
	if err != nil {
		return nil, time.Time{}, err
	}
	data, ok := files[file[0]]
	if !ok {
		return nil, time.Time{}, ErrNotExist
	}
	return data, time.Now(), nil
}
