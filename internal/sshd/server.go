// Package sshd is shellshawk's SSH server. It never gives access to the host
// operating system: only "session" channels are accepted, and a session can
// only run the BBS handler (docs/DESIGN.md §2).
package sshd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Defaults for Config fields left at zero.
const (
	// DefaultHandshakeTimeout bounds key exchange plus authentication. It is
	// generous because invite-code registration types a password at a
	// prompt (same as OpenSSH's LoginGraceTime).
	DefaultHandshakeTimeout = 120 * time.Second
	// DefaultMaxConns caps concurrent connections, including unauthenticated.
	DefaultMaxConns = 100
	// MaxAuthTries matches OpenSSH so agents holding several keys still work.
	MaxAuthTries = 6
	// maxSessionsPerConn caps "session" channels per connection.
	maxSessionsPerConn = 2
	// serverVersion deliberately carries no version number.
	serverVersion = "SSH-2.0-shellshawk"
)

// Config configures a Server.
type Config struct {
	Addr             string
	HostKey          ssh.Signer
	Auth             Authenticator
	Handler          SessionHandler
	SFTP             SFTPHandler   // nil = sftp subsystem refused
	MaxConns         int           // 0 → DefaultMaxConns
	HandshakeTimeout time.Duration // 0 → DefaultHandshakeTimeout
	Log              *slog.Logger
}

// Server is the SSH server.
type Server struct {
	addr             string
	sshConfig        *ssh.ServerConfig
	auth             Authenticator
	handler          SessionHandler
	sftp             SFTPHandler
	handshakeTimeout time.Duration
	slots            chan struct{} // connection semaphore
	log              *slog.Logger

	ctx    context.Context // cancelled by Shutdown
	cancel context.CancelFunc

	mu       sync.Mutex
	listener net.Listener
	conns    map[net.Conn]struct{}
	closing  bool
	wg       sync.WaitGroup
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	switch {
	case cfg.HostKey == nil:
		return nil, errors.New("sshd: host key is required")
	case cfg.Auth == nil:
		return nil, errors.New("sshd: authenticator is required")
	case cfg.Handler == nil:
		return nil, errors.New("sshd: session handler is required")
	case cfg.Log == nil:
		return nil, errors.New("sshd: logger is required")
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}

	s := &Server{
		addr:             cfg.Addr,
		auth:             cfg.Auth,
		handler:          cfg.Handler,
		sftp:             cfg.SFTP,
		handshakeTimeout: cfg.HandshakeTimeout,
		slots:            make(chan struct{}, cfg.MaxConns),
		log:              cfg.Log.With("component", "sshd"),
		conns:            map[net.Conn]struct{}{},
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.sshConfig = s.newSSHConfig(cfg.Auth)
	s.sshConfig.AddHostKey(cfg.HostKey)
	return s, nil
}

func (s *Server) newSSHConfig(auth Authenticator) *ssh.ServerConfig {
	c := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: KeyExchanges,
			Ciphers:      Ciphers,
			MACs:         MACs,
		},
		PublicKeyAuthAlgorithms: UserSignatureAlgorithms,
		MaxAuthTries:            MaxAuthTries,
		ServerVersion:           serverVersion,
	}

	c.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		info := connInfo(meta)
		if err := CheckUserKey(key); err != nil {
			s.log.Info("public key refused by policy", "conn_id", info.ConnID, "key_type", key.Type(), "reason", err)
			return nil, err
		}
		id, err := auth.PublicKey(info, key)
		if err != nil {
			return nil, err
		}
		if (id.Mode != ModeMember && id.Mode != ModePending) || id.UserID == "" {
			s.log.Error("authenticator returned invalid identity for public key", "conn_id", info.ConnID, "mode", id.Mode)
			return nil, ErrDenied
		}
		id.InviteCode = ""
		id.KeyFingerprint = ssh.FingerprintSHA256(key)
		return identityToPermissions(id), nil
	}

	c.PasswordCallback = func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		info := connInfo(meta)
		id, err := auth.Password(info, password)
		if err != nil {
			return nil, err
		}
		// Invariant: a password never grants full access.
		valid := (id.Mode == ModeRegister && id.UserID == "" && id.InviteCode != "") ||
			(id.Mode == ModeAddKey && id.UserID != "")
		if !valid {
			s.log.Error("authenticator returned invalid identity for password", "conn_id", info.ConnID, "mode", id.Mode)
			return nil, ErrDenied
		}
		id.KeyFingerprint = ""
		return identityToPermissions(id), nil
	}

	c.AuthLogCallback = func(meta ssh.ConnMetadata, method string, err error) {
		if method == "none" {
			return // every client probes "none" first
		}
		s.log.Debug("auth attempt", "conn_id", connID(meta), "method", method, "ok", err == nil)
	}
	return c
}

// connID derives a log-correlation ID from the SSH session ID, which is
// unique per connection and already random.
func connID(meta ssh.ConnMetadata) string {
	id := meta.SessionID()
	if len(id) > 8 {
		id = id[:8]
	}
	return hex.EncodeToString(id)
}

func connInfo(meta ssh.ConnMetadata) ConnInfo {
	info := ConnInfo{User: meta.User(), ConnID: connID(meta)}
	if ap, err := netip.ParseAddrPort(meta.RemoteAddr().String()); err == nil {
		info.RemoteIP = ap.Addr().Unmap()
	}
	return info
}

// ListenAndServe listens on the configured address and serves until Shutdown.
func (s *Server) ListenAndServe() error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("sshd: listen: %w", err)
	}
	return s.Serve(l)
}

// ErrServerClosed is returned by Serve after Shutdown.
var ErrServerClosed = errors.New("sshd: server closed")

// Serve accepts connections on l until Shutdown. It takes ownership of l.
func (s *Server) Serve(l net.Listener) error {
	s.mu.Lock()
	if s.closing {
		s.mu.Unlock()
		l.Close()
		return ErrServerClosed
	}
	s.listener = l
	s.mu.Unlock()
	s.log.Info("ssh listening", "addr", l.Addr().String())

	for {
		c, err := l.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				return ErrServerClosed
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return fmt.Errorf("sshd: accept: %w", err)
		}

		select {
		case s.slots <- struct{}{}:
		default:
			s.log.Warn("connection refused: limit reached", "max_conns", cap(s.slots))
			c.Close()
			continue
		}
		if !s.track(c) {
			<-s.slots
			c.Close()
			return ErrServerClosed
		}
		go func() {
			defer s.wg.Done()
			defer func() { <-s.slots }()
			defer s.untrack(c)
			s.serveConn(c)
		}()
	}
}

func (s *Server) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing {
		return false
	}
	s.conns[c] = struct{}{}
	s.wg.Add(1)
	return true
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	c.Close()
}

func (s *Server) serveConn(c net.Conn) {
	// The deadline covers key exchange and authentication only.
	_ = c.SetDeadline(time.Now().Add(s.handshakeTimeout))
	sconn, chans, reqs, err := ssh.NewServerConn(c, s.sshConfig)
	if err != nil {
		s.log.Debug("handshake failed", "err", err)
		return
	}
	_ = c.SetDeadline(time.Time{})
	defer sconn.Close()

	id, ok := identityFromPermissions(sconn.Permissions)
	cid := connID(sconn)
	log := s.log.With("conn_id", cid)
	if !ok {
		// Unreachable unless the callbacks above are changed incorrectly.
		log.Error("authenticated connection without identity; closing")
		return
	}
	log.Info("connection authenticated", "mode", id.Mode, "client", sanitizeForLog(string(sconn.ClientVersion())))
	if rec, ok := s.auth.(LoginRecorder); ok {
		rec.RecordLogin(s.ctx, id)
	}

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	go func() {
		_ = sconn.Wait()
		cancel()
	}()

	// Global requests (tcpip-forward, …) are all refused.
	go discardGlobalRequests(reqs, log)

	var sessions sync.WaitGroup
	defer sessions.Wait()
	active := 0
	var activeMu sync.Mutex
	for {
		select {
		case <-ctx.Done():
			return
		case nc, ok := <-chans:
			if !ok {
				return
			}
			if nc.ChannelType() != "session" {
				log.Info("channel refused", "type", sanitizeForLog(nc.ChannelType()))
				_ = nc.Reject(ssh.Prohibited, "only interactive sessions are permitted")
				continue
			}
			activeMu.Lock()
			if active >= maxSessionsPerConn {
				activeMu.Unlock()
				log.Info("channel refused: too many sessions")
				_ = nc.Reject(ssh.ResourceShortage, "too many sessions")
				continue
			}
			active++
			activeMu.Unlock()

			ch, chReqs, err := nc.Accept()
			if err != nil {
				activeMu.Lock()
				active--
				activeMu.Unlock()
				log.Warn("accept channel", "err", err)
				continue
			}
			sessions.Go(func() {
				defer func() { activeMu.Lock(); active--; activeMu.Unlock() }()
				s.serveSession(ctx, id, cid, ch, chReqs, log)
			})
		}
	}
}

func discardGlobalRequests(reqs <-chan *ssh.Request, log *slog.Logger) {
	for r := range reqs {
		if r.Type != "keepalive@openssh.com" {
			log.Info("global request refused", "type", sanitizeForLog(r.Type))
		}
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
	}
}

// Shutdown stops accepting connections, cancels every session's context, and
// waits for connections to finish. If ctx expires first, remaining
// connections are closed forcibly and ctx's error is returned.
func (s *Server) Shutdown(ctx context.Context) error {
	// Cancel before closing the listener so Serve sees ctx.Err() when its
	// Accept fails and returns ErrServerClosed rather than an accept error.
	s.cancel()
	s.mu.Lock()
	s.closing = true
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		s.log.Info("ssh server stopped")
		return nil
	case <-ctx.Done():
		s.mu.Lock()
		n := len(s.conns)
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		s.log.Warn("ssh shutdown timed out; connections closed forcibly", "count", n)
		<-done
		return ctx.Err()
	}
}
