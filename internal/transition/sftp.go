package transition

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
)

// Mount serves the profiles over SFTP to members holding
// core.transitions.manage:
//
//	/text/<slug>/<file>
//
// Uploading a file into a directory that does not exist yet creates the
// profile; mkdir creates an empty one and rmdir removes an empty one.
// Files are stored cleaned (see Clean), so reading one back returns the
// text as it is shown.
func (s *Service) Mount() sftpd.Mount {
	return sftpd.Mount{Name: "text", AnyOf: []string{perm.TransitionsManage}, FS: &textFS{s: s}}
}

type textFS struct{ s *Service }

var _ sftpd.ManagedFS = (*textFS)(nil)

func (f *textFS) profile(ctx context.Context, slug string) (Profile, error) {
	p, err := f.s.ProfileBySlug(ctx, slug)
	if errors.Is(err, ErrNotFound) {
		return Profile{}, sftpd.ErrNotExist
	}
	return p, err
}

// refused turns the service's validation errors into a refusal the SFTP
// server reports without logging it as a fault.
func refused(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return sftpd.ErrNotExist
	case errors.Is(err, perm.ErrForbidden):
		return sftpd.ErrPermission
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrExists), errors.Is(err, ErrTooMany), errors.Is(err, ErrNotEmpty):
		return fmt.Errorf("%w: %w", sftpd.ErrRefused, err)
	}
	return err
}

func (f *textFS) List(ctx context.Context, u sftpd.User, dir []string) ([]sftpd.Entry, error) {
	switch len(dir) {
	case 0:
		ps, err := f.s.Profiles(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]sftpd.Entry, 0, len(ps))
		for _, p := range ps {
			out = append(out, sftpd.Entry{Name: p.Slug, Dir: true})
		}
		return out, nil
	case 1:
		p, err := f.profile(ctx, dir[0])
		if err != nil {
			return nil, err
		}
		files, err := f.s.Files(ctx, p.ID)
		if err != nil {
			return nil, err
		}
		out := make([]sftpd.Entry, 0, len(files))
		for _, fl := range files {
			out = append(out, sftpd.Entry{Name: fl.Name, Size: int64(fl.Size), ModTime: fl.Updated})
		}
		return out, nil
	}
	return nil, sftpd.ErrNotExist
}

func (f *textFS) Read(ctx context.Context, u sftpd.User, file []string) ([]byte, time.Time, error) {
	if len(file) != 2 {
		return nil, time.Time{}, sftpd.ErrNotExist
	}
	p, err := f.profile(ctx, file[0])
	if err != nil {
		return nil, time.Time{}, err
	}
	body, updated, err := f.s.ReadFile(ctx, p.ID, file[1])
	if err != nil {
		return nil, time.Time{}, refused(err)
	}
	return []byte(body + "\n"), updated, nil
}

func (f *textFS) Write(ctx context.Context, u sftpd.User, file []string, data []byte) error {
	if len(file) != 2 {
		return sftpd.ErrPermission
	}
	return refused(f.s.Upload(ctx, u.ID, file[0], file[1], data))
}

func (f *textFS) Remove(ctx context.Context, u sftpd.User, file []string) error {
	if len(file) != 2 {
		return sftpd.ErrPermission
	}
	p, err := f.profile(ctx, file[0])
	if err != nil {
		return err
	}
	return refused(f.s.DeleteFile(ctx, u.ID, p.ID, file[1]))
}

func (f *textFS) Mkdir(ctx context.Context, u sftpd.User, dir []string) error {
	if len(dir) != 1 {
		return sftpd.ErrPermission
	}
	_, err := f.s.CreateProfile(ctx, u.ID, dir[0])
	return refused(err)
}

func (f *textFS) Rmdir(ctx context.Context, u sftpd.User, dir []string) error {
	if len(dir) != 1 {
		return sftpd.ErrPermission
	}
	p, err := f.profile(ctx, dir[0])
	if err != nil {
		return err
	}
	return refused(f.s.DeleteProfile(ctx, u.ID, p.ID, true))
}
