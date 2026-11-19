package transition

import (
	"errors"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
)

func TestTextFS(t *testing.T) {
	s, _, ctx := setup(t)
	m := s.Mount()
	if m.Name != "text" || len(m.AnyOf) != 1 || m.AnyOf[0] != perm.TransitionsManage {
		t.Fatalf("mount = %+v", m)
	}
	fs := m.FS.(sftpd.ManagedFS)
	u := sftpd.User{ID: admin}

	steps := []struct {
		name string
		do   func() error
		want error // nil, sftpd.ErrNotExist, sftpd.ErrPermission or sftpd.ErrRefused
	}{
		{"mkdir", func() error { return fs.Mkdir(ctx, u, []string{"enter"}) }, nil},
		{"mkdir again", func() error { return fs.Mkdir(ctx, u, []string{"enter"}) }, sftpd.ErrRefused},
		{"mkdir bad name", func() error { return fs.Mkdir(ctx, u, []string{"Big Name"}) }, sftpd.ErrRefused},
		{"mkdir nested", func() error { return fs.Mkdir(ctx, u, []string{"enter", "sub"}) }, sftpd.ErrPermission},
		{"upload", func() error { return fs.Write(ctx, u, []string{"enter", "logo.txt"}, []byte("LOGO\r\n")) }, nil},
		{"upload creates a profile", func() error { return fs.Write(ctx, u, []string{"exit", "bye.ans"}, []byte("\x1b[31mBYE")) }, nil},
		{"upload empty text", func() error { return fs.Write(ctx, u, []string{"exit", "blank.txt"}, []byte("  \n")) }, sftpd.ErrRefused},
		{"upload outside a profile", func() error { return fs.Write(ctx, u, []string{"top.txt"}, []byte("x")) }, sftpd.ErrPermission},
		{"upload by a member", func() error { return fs.Write(ctx, sftpd.User{ID: member}, []string{"exit", "x.txt"}, []byte("x")) }, sftpd.ErrPermission},
		{"rmdir with files", func() error { return fs.Rmdir(ctx, u, []string{"exit"}) }, sftpd.ErrRefused},
		{"remove", func() error { return fs.Remove(ctx, u, []string{"exit", "bye.ans"}) }, nil},
		{"remove missing", func() error { return fs.Remove(ctx, u, []string{"exit", "bye.ans"}) }, sftpd.ErrNotExist},
		{"rmdir", func() error { return fs.Rmdir(ctx, u, []string{"exit"}) }, nil},
		{"rmdir missing", func() error { return fs.Rmdir(ctx, u, []string{"exit"}) }, sftpd.ErrNotExist},
	}
	for _, st := range steps {
		err := st.do()
		if (st.want == nil) != (err == nil) || (st.want != nil && !errors.Is(err, st.want)) {
			t.Errorf("%s: err = %v, want %v", st.name, err, st.want)
		}
	}

	root, _ := fs.List(ctx, u, nil)
	if len(root) != 1 || root[0].Name != "enter" || !root[0].Dir {
		t.Errorf("root = %+v", root)
	}
	files, _ := fs.List(ctx, u, []string{"enter"})
	if len(files) != 1 || files[0].Name != "logo.txt" || files[0].Size != 4 {
		t.Errorf("files = %+v", files)
	}
	if _, err := fs.List(ctx, u, []string{"nope"}); !errors.Is(err, sftpd.ErrNotExist) {
		t.Errorf("list missing = %v", err)
	}
	if b, _, err := fs.Read(ctx, u, []string{"enter", "logo.txt"}); err != nil || string(b) != "LOGO\n" {
		t.Errorf("read = %q, %v", b, err)
	}
	if _, _, err := fs.Read(ctx, u, []string{"enter", "nope.txt"}); !errors.Is(err, sftpd.ErrNotExist) {
		t.Errorf("read missing = %v", err)
	}
}
