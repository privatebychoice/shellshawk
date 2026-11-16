// Command shellshawk runs the shellshawk BBS server.
//
// Configuration is read from environment variables; see README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.privatebychoice.com/shellshawk/internal/config"
	"go.privatebychoice.com/shellshawk/internal/logging"
	"go.privatebychoice.com/shellshawk/internal/sshd"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/version"
	"go.privatebychoice.com/shellshawk/internal/web"
)

const shutdownTimeout = 10 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "shellshawk:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	log := logging.New(os.Stderr, cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)

	v := version.Get()
	log.Info("starting shellshawk", "version", v.Version, "commit", v.Commit, "build_date", v.BuildDate)

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

	if !cfg.SSHEnabled() && !cfg.WebEnabled() {
		log.Warn("neither SSH nor web is enabled; nothing to serve",
			"hint", "set "+config.EnvSSHAddr+" and/or "+config.EnvHTTPAddr)
	}

	errc := make(chan error, 2)

	var sshSrv *sshd.Server
	if cfg.SSHEnabled() {
		hostKey, err := sshd.LoadOrCreateHostKey(cfg.SSHHostKeyPath, log)
		if err != nil {
			return err
		}
		sshSrv, err = sshd.New(sshd.Config{
			Addr:    cfg.SSHAddr,
			HostKey: hostKey,
			// Accounts arrive in stage 3; until then nobody can log in.
			Auth:     sshd.DenyAll{},
			Handler:  unavailableHandler{},
			MaxConns: cfg.SSHMaxConns,
			Log:      log,
		})
		if err != nil {
			return err
		}
		log.Warn("SSH logins are disabled until account support is implemented (stage 3)")
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

// unavailableHandler is the session handler until the TUI exists (stage 4).
// With sshd.DenyAll in place it is never reached; it exists because the
// server requires a handler.
type unavailableHandler struct{}

func (unavailableHandler) HandleShell(_ context.Context, s *sshd.Session) {
	_, _ = io.WriteString(s, "The shellshawk BBS interface is not available yet.\r\n")
}
