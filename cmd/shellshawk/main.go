// Command shellshawk runs the shellshawk BBS server.
//
// Usage:
//
//	shellshawk                   run the server
//	shellshawk bootstrap-invite  print a one-time invite for the first administrator
//
// Configuration is read from environment variables; see README.md.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/config"
	"go.privatebychoice.com/shellshawk/internal/logging"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/sshd"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/version"
	"go.privatebychoice.com/shellshawk/internal/web"
)

const (
	shutdownTimeout    = 10 * time.Second
	auditPurgeInterval = 24 * time.Hour
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "shellshawk:", err)
		os.Exit(1)
	}
}

// app holds the services shared by the server and CLI commands.
type app struct {
	cfg   config.Config
	log   *slog.Logger
	db    *sql.DB
	perms *perm.Service
	auth  *auth.Service
}

func run(args []string) error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	log := logging.New(os.Stderr, cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, cfg.DBPath, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Error("close database", "err", err)
		}
	}()
	perms := perm.NewService(db, perm.NewRegistry(), nil, log)
	a := &app{cfg: cfg, log: log, db: db, perms: perms, auth: auth.NewService(db, perms, cfg.InviteUser, nil, log)}

	switch {
	case len(args) == 0:
		return a.serve(ctx)
	case len(args) == 1 && args[0] == "bootstrap-invite":
		return a.bootstrapInvite(ctx, os.Stdout)
	default:
		return fmt.Errorf("unknown command %q (commands: bootstrap-invite)", args)
	}
}

// bootstrapInvite prints a single-use admin invite. It refuses once any
// active administrator exists.
func (a *app) bootstrapInvite(ctx context.Context, out io.Writer) error {
	code, err := a.auth.CreateBootstrapInvite(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Administrator invite (single use, valid %s):\n\n    %s\n\n", auth.BootstrapTTL, code)
	fmt.Fprintf(out, "Connect with SSH as user %q and enter the code as the password.\n", a.cfg.InviteUser)
	return nil
}

func (a *app) serve(ctx context.Context) error {
	cfg, log := a.cfg, a.log
	v := version.Get()
	log.Info("starting shellshawk", "version", v.Version, "commit", v.Commit, "build_date", v.BuildDate)

	if n, err := perm.CountActiveAdmins(ctx, a.db); err != nil {
		return err
	} else if n == 0 {
		log.Warn("no active administrator; run `shellshawk bootstrap-invite` to create the first one")
	}
	if !cfg.SSHEnabled() && !cfg.WebEnabled() {
		log.Warn("neither SSH nor web is enabled; nothing to serve",
			"hint", "set "+config.EnvSSHAddr+" and/or "+config.EnvHTTPAddr)
	}

	go a.purgeAuditLog(ctx)

	errc := make(chan error, 2)

	var sshSrv *sshd.Server
	if cfg.SSHEnabled() {
		hostKey, err := sshd.LoadOrCreateHostKey(cfg.SSHHostKeyPath, log)
		if err != nil {
			return err
		}
		sshSrv, err = sshd.New(sshd.Config{
			Addr:     cfg.SSHAddr,
			HostKey:  hostKey,
			Auth:     auth.NewSSHAuthenticator(a.auth),
			Handler:  unavailableHandler{},
			MaxConns: cfg.SSHMaxConns,
			Log:      log,
		})
		if err != nil {
			return err
		}
		go func() {
			if err := sshSrv.ListenAndServe(); !errors.Is(err, sshd.ErrServerClosed) {
				errc <- err
			}
		}()
	} else {
		log.Info("ssh disabled", "hint", config.EnvSSHAddr+" not set")
	}

	var webSrv *http.Server
	if cfg.WebEnabled() {
		webSrv = web.NewServer(cfg.HTTPAddr, log)
		go func() {
			log.Info("web interface listening", "addr", cfg.HTTPAddr)
			if err := webSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("web server: %w", err)
			}
		}()
	} else {
		log.Info("web interface disabled", "hint", config.EnvHTTPAddr+" not set")
	}

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case runErr = <-errc:
		log.Error("server failed; shutting down", "err", runErr)
	}

	sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if sshSrv != nil {
		if err := sshSrv.Shutdown(sctx); err != nil {
			log.Warn("ssh server shutdown", "err", err)
		}
	}
	if webSrv != nil {
		if err := webSrv.Shutdown(sctx); err != nil {
			log.Warn("web server shutdown", "err", err)
		}
	}
	log.Info("stopped")
	return runErr
}

// purgeAuditLog deletes expired audit entries at startup and then daily.
func (a *app) purgeAuditLog(ctx context.Context) {
	retention := time.Duration(a.cfg.AuditRetentionDays) * 24 * time.Hour
	t := time.NewTicker(auditPurgeInterval)
	defer t.Stop()
	for {
		n, err := audit.Purge(ctx, a.db, time.Now(), retention)
		switch {
		case err != nil && ctx.Err() == nil:
			a.log.Error("audit purge failed", "err", err)
		case n > 0:
			a.log.Info("audit entries purged", "count", n, "retention_days", a.cfg.AuditRetentionDays)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// unavailableHandler is the session handler until the TUI exists (stage 4).
// Logins now work, but there is nothing to show yet; it says so and exits.
type unavailableHandler struct{}

func (unavailableHandler) HandleShell(_ context.Context, s *sshd.Session) {
	var msg string
	switch s.Identity.Mode {
	case sshd.ModeRegister:
		msg = "Your invite code is valid, but the registration screen is not built yet (stage 4)."
	case sshd.ModePending:
		msg = "Your account is awaiting approval."
	case sshd.ModeAddKey:
		msg = "Password accepted, but the add-key screen is not built yet (stage 4)."
	default:
		msg = "Login successful, but the BBS interface is not built yet (stage 4)."
	}
	_, _ = io.WriteString(s, msg+"\r\n")
}
