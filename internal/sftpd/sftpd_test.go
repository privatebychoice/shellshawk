package sftpd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/export"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/sshd"
	"go.privatebychoice.com/shellshawk/internal/store"
)

const testPassword = "a long enough test passphrase"

// memFS is a writable test mount holding files in memory.
type memFS struct {
	mu    sync.Mutex
	files map[string][]byte
	// failWrite makes Write fail with an internal error.
	failWrite bool
}

func (m *memFS) List(_ context.Context, _ User, dir []string) ([]Entry, error) {
	if len(dir) != 0 {
		return nil, ErrNotExist
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Entry
	for n, b := range m.files {
		out = append(out, Entry{Name: n, Size: int64(len(b))})
	}
	out = append(out, Entry{Name: "../escape"}) // must be filtered out
	return out, nil
}

func (m *memFS) Read(_ context.Context, _ User, file []string) ([]byte, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.files[strings.Join(file, "/")]
	if !ok {
		return nil, time.Time{}, ErrNotExist
	}
	return b, time.Now(), nil
}

func (m *memFS) Write(_ context.Context, u User, file []string, data []byte) error {
	if m.failWrite {
		return errors.New("database is on fire: internal detail")
	}
	if len(file) != 1 {
		return ErrPermission
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[file[0]] = append([]byte(u.Name+":"), data...)
	return nil
}

// readOnlyFS is a mount restricted by permission.
type readOnlyFS struct{}

func (readOnlyFS) List(context.Context, User, []string) ([]Entry, error) {
	return []Entry{{Name: "secret.txt", Size: 6}}, nil
}
func (readOnlyFS) Read(_ context.Context, _ User, f []string) ([]byte, time.Time, error) {
	if len(f) == 1 && f[0] == "secret.txt" {
		return []byte("secret"), time.Now(), nil
	}
	return nil, time.Time{}, ErrNotExist
}

type env struct {
	addr     string
	hostKey  ssh.PublicKey
	auth     *auth.Service
	perms    *perm.Service
	mem      *memFS
	admin    ssh.Signer
	adminID  int64
	member   ssh.Signer
	memberID int64
}

func newKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	return s, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
}

func start(t *testing.T, maxUpload int64) *env {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.DiscardHandler)
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "s.db"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	reg := perm.NewRegistry()
	reg.Register("vault.read", "read the vault")
	ps := perm.NewService(db, reg, nil, log)
	as := auth.NewService(db, ps, "new", nil, log)
	e := &env{auth: as, perms: ps, mem: &memFS{files: map[string][]byte{"hello.txt": []byte("hi")}}}

	code, _ := as.CreateBootstrapInvite(ctx)
	var line string
	e.admin, line = newKey(t)
	a, err := as.Register(ctx, code, auth.Registration{Username: "admin1", Password: testPassword, PublicKey: line})
	if err != nil {
		t.Fatal(err)
	}
	e.adminID = a.ID
	inv, _, _ := as.CreateInvite(ctx, a.ID, auth.InviteOptions{})
	e.member, line = newKey(t)
	m, err := as.Register(ctx, inv, auth.Registration{Username: "member1", Password: testPassword, PublicKey: line})
	if err != nil {
		t.Fatal(err)
	}
	e.memberID = m.ID

	srv, err := New(as, ps, maxUpload, log,
		MeMount(as, ps,
			export.Source{Export: func(_ context.Context, uid int64) ([]export.File, error) {
				return []export.File{{Name: "account.json", Data: []byte(fmt.Sprintf(`{"id":%d}`, uid))}}, nil
			}},
			export.Source{Name: "notes", Export: func(context.Context, int64) ([]export.File, error) {
				return []export.File{{Name: "notes.json", Data: []byte("[]")}, {Name: "../evil", Data: []byte("x")}}, nil
			}},
		),
		Mount{Name: "files", FS: e.mem},
		Mount{Name: "vault", AnyOf: []string{"vault.read"}, FS: readOnlyFS{}},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	host, _ := ssh.NewSignerFromKey(hostPriv)
	sshSrv, err := sshd.New(sshd.Config{
		HostKey: host, Auth: auth.NewSSHAuthenticator(as), Log: log, SFTP: srv,
		Handler: noShell{},
	})
	if err != nil {
		t.Fatal(err)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	go sshSrv.Serve(l)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		sshSrv.Shutdown(c)
	})
	e.addr, e.hostKey = l.Addr().String(), host.PublicKey()
	return e
}

type noShell struct{}

func (noShell) HandleShell(context.Context, *sshd.Session) {}

func (e *env) client(t *testing.T, user string, am ssh.AuthMethod) (*sftp.Client, error) {
	t.Helper()
	c, err := ssh.Dial("tcp", e.addr, &ssh.ClientConfig{
		User: user, Auth: []ssh.AuthMethod{am}, HostKeyCallback: ssh.FixedHostKey(e.hostKey), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	sc, err := sftp.NewClient(c)
	if err == nil {
		t.Cleanup(func() { sc.Close() })
	}
	return sc, err
}

func names(t *testing.T, sc *sftp.Client, dir string) []string {
	t.Helper()
	fis, err := sc.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", dir, err)
	}
	var out []string
	for _, fi := range fis {
		out = append(out, fi.Name())
	}
	slices.Sort(out)
	return out
}

func readFile(sc *sftp.Client, p string) (string, error) {
	f, err := sc.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	return string(b), err
}

func writeFile(sc *sftp.Client, p string, data []byte) error {
	f, err := sc.Create(p)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func TestBrowseAndRead(t *testing.T) {
	e := start(t, DefaultMaxUpload)
	member, err := e.client(t, "member1", ssh.PublicKeys(e.member))
	if err != nil {
		t.Fatal(err)
	}

	if got := names(t, member, "/"); !slices.Equal(got, []string{"files", "me"}) {
		t.Errorf("member root = %v (vault must be hidden)", got)
	}
	if got := names(t, member, "/files"); !slices.Equal(got, []string{"hello.txt"}) {
		t.Errorf("/files = %v (invalid names must be filtered)", got)
	}
	if got := names(t, member, "/me"); !slices.Equal(got, []string{"export", "keys.pub", "profile.md"}) {
		t.Errorf("/me = %v", got)
	}
	prof, err := readFile(member, "/me/profile.md")
	if err != nil || !strings.HasPrefix(prof, "# member1\n") || !strings.Contains(prof, "- Groups: member") {
		t.Errorf("profile.md = %q, %v", prof, err)
	}
	keys, _ := readFile(member, "/me/keys.pub")
	if !strings.HasPrefix(keys, "ssh-ed25519 ") || strings.Count(keys, "\n") != 1 {
		t.Errorf("keys.pub = %q", keys)
	}
	if got, err := readFile(member, "/files/../files/hello.txt"); err != nil || got != "hi" {
		t.Errorf("read via .. = %q, %v", got, err)
	}

	tests := []struct {
		name string
		path string
	}{
		{"missing file", "/files/nope.txt"},
		{"missing mount", "/etc/passwd"},
		{"traversal stays inside", "/../../etc/passwd"},
		{"hidden mount looks absent", "/vault/secret.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := readFile(member, tt.path); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("read %s err = %v, want not exist", tt.path, err)
			}
		})
	}
	if _, err := member.Stat("/vault"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("stat hidden mount = %v", err)
	}
	fi, err := member.Stat("/me/profile.md")
	if err != nil || fi.IsDir() || fi.Mode().Perm() != 0o444 {
		t.Errorf("stat profile = %v, %v", fi, err)
	}
}

func TestPermissionGrantedMountAndLiveRevocation(t *testing.T) {
	e := start(t, DefaultMaxUpload)
	ctx := context.Background()
	admin, err := e.client(t, "admin1", ssh.PublicKeys(e.admin))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := readFile(admin, "/vault/secret.txt"); err != nil || got != "secret" {
		t.Errorf("admin vault read = %q, %v", got, err)
	}

	member, _ := e.client(t, "member1", ssh.PublicKeys(e.member))
	if _, err := readFile(member, "/me/profile.md"); err != nil {
		t.Fatal(err)
	}
	// Locking the account takes effect on the next request in the open session.
	if err := e.auth.SetLocked(ctx, e.adminID, e.memberID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := readFile(member, "/me/profile.md"); !errors.Is(err, fs.ErrPermission) {
		t.Errorf("read after lock = %v, want permission denied", err)
	}
}

func TestUploads(t *testing.T) {
	e := start(t, 64)
	member, err := e.client(t, "member1", ssh.PublicKeys(e.member))
	if err != nil {
		t.Fatal(err)
	}

	if err := writeFile(member, "/files/new.txt", []byte("uploaded")); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if got := string(e.mem.files["new.txt"]); got != "member1:uploaded" {
		t.Errorf("stored = %q (mount must receive the uploading user)", got)
	}
	if got, _ := readFile(member, "/files/new.txt"); got != "member1:uploaded" {
		t.Errorf("read back = %q", got)
	}

	if err := writeFile(member, "/files/big.txt", bytes.Repeat([]byte("x"), 65)); err == nil {
		t.Error("oversized upload accepted")
	}
	if _, ok := e.mem.files["big.txt"]; ok {
		t.Error("oversized upload was stored")
	}

	tests := []struct {
		name string
		path string
	}{
		{"read-only mount", "/me/x.txt"},
		{"root", "/x.txt"},
		{"hidden mount", "/vault/x.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := writeFile(member, tt.path, []byte("x")); err == nil {
				t.Errorf("write to %s accepted", tt.path)
			}
		})
	}

	e.mem.failWrite = true
	err = writeFile(member, "/files/fail.txt", []byte("x"))
	if err == nil || strings.Contains(err.Error(), "on fire") {
		t.Errorf("internal write error = %v (must fail without leaking details)", err)
	}
}

func TestCommandsRefused(t *testing.T) {
	e := start(t, DefaultMaxUpload)
	member, _ := e.client(t, "member1", ssh.PublicKeys(e.member))
	cmds := map[string]func() error{
		"mkdir":   func() error { return member.Mkdir("/files/dir") },
		"remove":  func() error { return member.Remove("/files/hello.txt") },
		"rename":  func() error { return member.Rename("/files/hello.txt", "/files/x.txt") },
		"symlink": func() error { return member.Symlink("/files/hello.txt", "/files/link") },
		"rmdir":   func() error { return member.RemoveDirectory("/files") },
	}
	for name, do := range cmds {
		t.Run(name, func(t *testing.T) {
			if err := do(); !errors.Is(err, os.ErrPermission) {
				t.Errorf("%s err = %v, want permission denied", name, err)
			}
		})
	}
	if err := member.Chtimes("/files/hello.txt", time.Now(), time.Now()); err != nil {
		t.Errorf("setstat should be accepted as a no-op: %v", err)
	}
	if _, ok := e.mem.files["hello.txt"]; !ok {
		t.Error("file disappeared")
	}
}

func TestSFTPRequiresMemberKeyLogin(t *testing.T) {
	e := start(t, DefaultMaxUpload)
	// Password login (add-key mode) must not get SFTP.
	if _, err := e.client(t, "member1", ssh.Password(testPassword)); err == nil {
		t.Error("sftp allowed for a password (add-key) login")
	}
}

func TestNewValidation(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	tests := []struct {
		name   string
		max    int64
		mounts []Mount
	}{
		{"zero upload limit", 0, nil},
		{"huge upload limit", MaxMaxUpload + 1, nil},
		{"bad name", 1, []Mount{{Name: "Bad/Name", FS: readOnlyFS{}}}},
		{"no fs", 1, []Mount{{Name: "x1"}}},
		{"duplicate", 1, []Mount{{Name: "x1", FS: readOnlyFS{}}, {Name: "x1", FS: readOnlyFS{}}}},
	}
	for _, tt := range tests {
		if _, err := New(nil, nil, tt.max, log, tt.mounts...); err == nil {
			t.Errorf("%s: accepted", tt.name)
		}
	}
}

// TestInterruptedUploadNotStored: pkg/sftp still calls Close on an upload
// when the connection drops, after reporting the error via TransferError.
func TestInterruptedUploadNotStored(t *testing.T) {
	mem := &memFS{files: map[string][]byte{}}
	h := &handler{ctx: context.Background(), log: slog.New(slog.DiscardHandler)}
	tests := []struct {
		name      string
		interrupt bool
		wantSaved bool
	}{
		{"complete", false, true},
		{"connection lost", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delete(mem.files, "f.txt")
			w := &upload{h: h, fs: mem, user: User{Name: "u"}, file: []string{"f.txt"}, max: 100}
			if _, err := w.WriteAt([]byte("part"), 0); err != nil {
				t.Fatal(err)
			}
			if tt.interrupt {
				w.TransferError(io.ErrUnexpectedEOF)
			}
			err := w.Close()
			_, saved := mem.files["f.txt"]
			if saved != tt.wantSaved || (err == nil) != tt.wantSaved {
				t.Errorf("saved = %v, Close err = %v", saved, err)
			}
		})
	}
	// Writes at an offset fill the gap; writes past the limit fail.
	w := &upload{h: h, fs: mem, user: User{Name: "u"}, file: []string{"g.txt"}, max: 8}
	w.WriteAt([]byte("cd"), 2)
	w.WriteAt([]byte("ab"), 0)
	if string(w.buf) != "abcd" {
		t.Errorf("buffer = %q", w.buf)
	}
	if _, err := w.WriteAt([]byte("xyz"), 6); err == nil {
		t.Error("write past the limit accepted")
	}
}

func TestZeroModTimeReplaced(t *testing.T) {
	if fi := (fileInfo{Entry: Entry{Name: "d", Dir: true}}); fi.ModTime().IsZero() {
		t.Error("zero mod time reported")
	}
}

func TestExport(t *testing.T) {
	e := start(t, DefaultMaxUpload)
	member, _ := e.client(t, "member1", ssh.PublicKeys(e.member))
	if got := names(t, member, "/me/export"); !slices.Equal(got, []string{"account.json", "notes"}) {
		t.Errorf("/me/export = %v", got)
	}
	if got := names(t, member, "/me/export/notes"); !slices.Equal(got, []string{"notes.json"}) {
		t.Errorf("/me/export/notes = %v (invalid names must be dropped)", got)
	}
	acct, err := readFile(member, "/me/export/account.json")
	if err != nil || acct != fmt.Sprintf(`{"id":%d}`, e.memberID) {
		t.Errorf("account.json = %q, %v (must be the requesting member's own data)", acct, err)
	}
	if _, err := readFile(member, "/me/export/nope/x.json"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("unknown export dir err = %v", err)
	}
}
