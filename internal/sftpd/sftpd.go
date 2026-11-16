// Package sftpd serves SFTP from a virtual file system (docs/DESIGN.md §10).
// Nothing maps to the host's files: the root holds one directory per mount
// ("me" for the member's own data, plus any plugin mounts), and each mount
// produces its listings and file contents from the database.
//
// Only the github.com/pkg/sftp RequestServer API is used; its OS-backed
// server is never constructed (enforced by internal/archtest).
package sftpd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/pkg/sftp"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/sshd"
)

// Upload size limits.
const (
	DefaultMaxUpload = 1 << 20  // 1 MiB
	MaxMaxUpload     = 64 << 20 // uploads are buffered in memory
)

// Errors a mount returns. They map to the SFTP "no such file" and
// "permission denied" statuses.
var (
	ErrNotExist   = fs.ErrNotExist
	ErrPermission = fs.ErrPermission
)

// User is the member making a request.
type User struct {
	ID    int64
	Name  string
	Perms perm.Set
}

// Entry is a file or directory in a listing.
type Entry struct {
	Name    string
	Dir     bool
	Size    int64
	ModTime time.Time
}

// FS is a mount's read-only view. Paths are relative to the mount, split
// into segments; nil is the mount's root directory.
type FS interface {
	List(ctx context.Context, u User, dir []string) ([]Entry, error)
	Read(ctx context.Context, u User, file []string) ([]byte, time.Time, error)
}

// WritableFS also accepts uploads. Write receives the complete file; it is
// called only after a transfer finished without error.
type WritableFS interface {
	FS
	Write(ctx context.Context, u User, file []string, data []byte) error
}

// Mount is a top-level directory.
type Mount struct {
	Name  string   // directory name under /
	AnyOf []string // permissions of which one is needed; empty = all members
	FS    FS
}

func (m Mount) allowed(set perm.Set) bool {
	if len(m.AnyOf) == 0 {
		return true
	}
	for _, p := range m.AnyOf {
		if set.Has(p) {
			return true
		}
	}
	return false
}

var mountName = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

// Server serves SFTP sessions. It implements sshd.SFTPHandler.
type Server struct {
	mounts    map[string]Mount
	order     []string
	auth      *auth.Service
	perms     *perm.Service
	maxUpload int64
	log       *slog.Logger
}

var _ sshd.SFTPHandler = (*Server)(nil)

// New validates the mounts and returns a Server.
func New(a *auth.Service, p *perm.Service, maxUpload int64, log *slog.Logger, mounts ...Mount) (*Server, error) {
	if maxUpload <= 0 || maxUpload > MaxMaxUpload {
		return nil, fmt.Errorf("sftpd: max upload must be 1 to %d bytes", MaxMaxUpload)
	}
	s := &Server{mounts: map[string]Mount{}, auth: a, perms: p, maxUpload: maxUpload, log: log.With("component", "sftpd")}
	for _, m := range mounts {
		if !mountName.MatchString(m.Name) || m.FS == nil {
			return nil, fmt.Errorf("sftpd: invalid mount %q", m.Name)
		}
		if _, dup := s.mounts[m.Name]; dup {
			return nil, fmt.Errorf("sftpd: duplicate mount %q", m.Name)
		}
		s.mounts[m.Name] = m
		s.order = append(s.order, m.Name)
	}
	return s, nil
}

// HandleSFTP implements sshd.SFTPHandler.
func (s *Server) HandleSFTP(ctx context.Context, sess *sshd.Session) {
	log := s.log.With("conn_id", sess.ConnID)
	uid, err := strconv.ParseInt(sess.Identity.UserID, 10, 64)
	if err != nil {
		log.Error("sftp session without a valid user id", "err", err)
		return
	}
	log = log.With("user_id", uid)
	h := &handler{s: s, ctx: ctx, uid: uid, log: log}
	rs := sftp.NewRequestServer(sess, sftp.Handlers{FileGet: h, FilePut: h, FileCmd: h, FileList: h})
	stop := context.AfterFunc(ctx, func() { rs.Close() })
	defer stop()
	log.Info("sftp session started")
	if err := rs.Serve(); err != nil && !errors.Is(err, io.EOF) {
		log.Info("sftp session ended", "err", err)
		return
	}
	log.Info("sftp session ended")
}

// handler serves one SFTP session's requests.
type handler struct {
	s   *Server
	ctx context.Context
	uid int64
	log *slog.Logger
}

// user loads the member fresh for every request, so locking an account or
// revoking a permission takes effect immediately.
func (h *handler) user() (User, error) {
	u, err := h.s.auth.UserByID(h.ctx, h.uid)
	if err != nil {
		return User{}, err
	}
	if u.Status != auth.StatusActive {
		return User{}, ErrPermission
	}
	set, err := h.s.perms.Permissions(h.ctx, h.uid)
	if err != nil {
		return User{}, err
	}
	return User{ID: u.ID, Name: u.Username, Perms: set}, nil
}

// resolve splits an absolute, already-cleaned path and finds its mount.
// Mounts the member may not use are reported as not existing.
func (h *handler) resolve(p string, u User) (Mount, []string, bool, error) {
	p = path.Clean("/" + p)
	if p == "/" {
		return Mount{}, nil, true, nil // the root
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	m, ok := h.s.mounts[segs[0]]
	if !ok || !m.allowed(u.Perms) {
		return Mount{}, nil, false, ErrNotExist
	}
	return m, segs[1:], false, nil
}

// status translates errors for the client. pkg/sftp maps "not exist"
// itself but only recognises "permission denied" from OS syscall errors.
func status(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return sftp.ErrSSHFxPermissionDenied
	}
	return err
}

// Fileread implements sftp.FileReader.
func (h *handler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	ra, err := h.fileread(r)
	return ra, status(err)
}

// Filelist implements sftp.FileLister.
func (h *handler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	l, err := h.filelist(r)
	return l, status(err)
}

// Filewrite implements sftp.FileWriter.
func (h *handler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	w, err := h.filewrite(r)
	return w, status(err)
}

// Filecmd implements sftp.FileCmder.
func (h *handler) Filecmd(r *sftp.Request) error { return status(h.filecmd(r)) }

// ---- reading ---------------------------------------------------------------

// fileread serves sftp.FileReader.
func (h *handler) fileread(r *sftp.Request) (io.ReaderAt, error) {
	u, err := h.user()
	if err != nil {
		return nil, err
	}
	m, rel, root, err := h.resolve(r.Filepath, u)
	if err != nil {
		return nil, err
	}
	if root || len(rel) == 0 {
		return nil, sftp.ErrSSHFxFailure // a directory
	}
	data, _, err := m.FS.Read(h.ctx, u, rel)
	if err != nil {
		return nil, h.mountErr("read", r.Filepath, err)
	}
	h.log.Debug("sftp read", "mount", m.Name, "bytes", len(data))
	return bytes.NewReader(data), nil
}

// mountErr passes the expected errors through and logs anything else,
// returning a generic failure so internal details never reach the client.
func (h *handler) mountErr(op, p string, err error) error {
	if errors.Is(err, ErrNotExist) || errors.Is(err, ErrPermission) {
		return err
	}
	h.log.Error("sftp mount error", "op", op, "err", err)
	return sftp.ErrSSHFxFailure
}

// ---- listing ---------------------------------------------------------------

// filelist serves sftp.FileLister.
func (h *handler) filelist(r *sftp.Request) (sftp.ListerAt, error) {
	u, err := h.user()
	if err != nil {
		return nil, err
	}
	m, rel, root, err := h.resolve(r.Filepath, u)
	if err != nil {
		return nil, err
	}
	switch r.Method {
	case "List":
		if root {
			var out listerAt
			for _, name := range h.s.order {
				if h.s.mounts[name].allowed(u.Perms) {
					out = append(out, fileInfo{Entry: Entry{Name: name, Dir: true}})
				}
			}
			return out, nil
		}
		entries, err := m.FS.List(h.ctx, u, rel)
		if err != nil {
			return nil, h.mountErr("list", r.Filepath, err)
		}
		_, writable := m.FS.(WritableFS)
		var out listerAt
		for _, e := range entries {
			if !validName(e.Name) {
				h.log.Warn("mount listed an invalid file name; skipped", "mount", m.Name)
				continue
			}
			out = append(out, fileInfo{Entry: e, writable: writable})
		}
		return out, nil

	case "Stat":
		if root {
			return listerAt{fileInfo{Entry: Entry{Name: "/", Dir: true}}}, nil
		}
		if len(rel) == 0 {
			return listerAt{fileInfo{Entry: Entry{Name: m.Name, Dir: true}}}, nil
		}
		entries, err := m.FS.List(h.ctx, u, rel[:len(rel)-1])
		if err != nil {
			return nil, h.mountErr("stat", r.Filepath, err)
		}
		_, writable := m.FS.(WritableFS)
		for _, e := range entries {
			if e.Name == rel[len(rel)-1] && validName(e.Name) {
				return listerAt{fileInfo{Entry: e, writable: writable}}, nil
			}
		}
		return nil, ErrNotExist
	}
	return nil, sftp.ErrSSHFxOpUnsupported // Readlink
}

// validName rejects names that could escape a directory or confuse a
// terminal when listed.
func validName(n string) bool {
	if n == "" || n == "." || n == ".." || strings.ContainsAny(n, "/\\") {
		return false
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

type listerAt []os.FileInfo

// ListAt implements sftp.ListerAt.
func (l listerAt) ListAt(out []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(out, l[offset:])
	if offset+int64(n) >= int64(len(l)) {
		return n, io.EOF
	}
	return n, nil
}

type fileInfo struct {
	Entry
	writable bool
}

func (f fileInfo) Name() string { return f.Entry.Name }
func (f fileInfo) Size() int64  { return f.Entry.Size }

// processStart is shown as the time of entries that have none (such as
// the mount directories), instead of year 1.
var processStart = time.Now()

func (f fileInfo) ModTime() time.Time {
	if f.Entry.ModTime.IsZero() {
		return processStart
	}
	return f.Entry.ModTime
}
func (f fileInfo) IsDir() bool { return f.Dir }
func (f fileInfo) Sys() any    { return nil }
func (f fileInfo) Mode() os.FileMode {
	switch {
	case f.Dir:
		return os.ModeDir | 0o555
	case f.writable:
		return 0o644
	}
	return 0o444
}

// ---- writing and commands -------------------------------------------------

// filewrite serves sftp.FileWriter.
func (h *handler) filewrite(r *sftp.Request) (io.WriterAt, error) {
	u, err := h.user()
	if err != nil {
		return nil, err
	}
	m, rel, root, err := h.resolve(r.Filepath, u)
	if err != nil {
		return nil, err
	}
	w, ok := m.FS.(WritableFS)
	if root || !ok || len(rel) == 0 || !validName(rel[len(rel)-1]) {
		return nil, ErrPermission
	}
	return &upload{h: h, fs: w, mount: m.Name, user: u, file: rel, max: h.s.maxUpload}, nil
}

// upload buffers a file in memory and hands it to the mount only when the
// transfer completed: a dropped connection or an oversized file stores
// nothing.
type upload struct {
	h     *handler
	fs    WritableFS
	mount string
	user  User
	file  []string
	max   int64

	mu     sync.Mutex
	buf    []byte
	failed error
}

// WriteAt implements io.WriterAt.
func (w *upload) WriteAt(p []byte, off int64) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return 0, w.failed
	}
	end := off + int64(len(p))
	if off < 0 || end > w.max {
		w.failed = fmt.Errorf("upload exceeds the %d byte limit", w.max)
		return 0, sftp.ErrSSHFxFailure
	}
	if end > int64(len(w.buf)) {
		w.buf = append(w.buf, make([]byte, end-int64(len(w.buf)))...)
	}
	copy(w.buf[off:], p)
	return len(p), nil
}

// TransferError implements sftp.TransferError: the connection failed with
// the file still open.
func (w *upload) TransferError(err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed == nil {
		w.failed = err
	}
}

// Close commits a complete upload.
func (w *upload) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		w.h.log.Info("sftp upload discarded", "mount", w.mount, "reason", w.failed)
		return sftp.ErrSSHFxFailure
	}
	if err := w.fs.Write(w.h.ctx, w.user, w.file, w.buf); err != nil {
		return status(w.h.mountErr("write", "", err))
	}
	w.h.log.Info("sftp upload stored", "mount", w.mount, "bytes", len(w.buf))
	return nil
}

// filecmd serves sftp.FileCmder. Setstat (sent by clients after an
// upload to set times) is accepted and ignored; everything else — mkdir,
// rmdir, rename, remove, links — is refused.
func (h *handler) filecmd(r *sftp.Request) error {
	if r.Method == "Setstat" {
		return nil
	}
	h.log.Debug("sftp command refused", "method", r.Method)
	return ErrPermission
}
