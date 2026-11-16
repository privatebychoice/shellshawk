package sftpd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/perm"
)

// MeMount is /me: the member's own data, read-only.
//
//	/me/profile.md  account details in markdown
//	/me/keys.pub    the member's public keys, authorized_keys format
//
// The full data export (right of access) is added with the privacy work.
func MeMount(a *auth.Service, p *perm.Service) Mount {
	return Mount{Name: "me", FS: &meFS{auth: a, perms: p}}
}

type meFS struct {
	auth  *auth.Service
	perms *perm.Service
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
	if len(dir) != 0 {
		return nil, ErrNotExist
	}
	files, err := m.files(ctx, u)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	return []Entry{
		{Name: "keys.pub", Size: int64(len(files["keys.pub"])), ModTime: now},
		{Name: "profile.md", Size: int64(len(files["profile.md"])), ModTime: now},
	}, nil
}

// Read implements FS.
func (m *meFS) Read(ctx context.Context, u User, file []string) ([]byte, time.Time, error) {
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
