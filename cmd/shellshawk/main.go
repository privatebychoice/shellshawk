// Command shellshawk runs the shellshawk BBS server.
//
// Configuration is read from environment variables; see README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.privatebychoice.com/shellshawk/internal/config"
	"go.privatebychoice.com/shellshawk/internal/logging"
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

	errc := make(chan error, 1)
	var srv *http.Server
	if cfg.WebEnabled() {
		srv = web.NewServer(cfg.HTTPAddr, log)
		go func() {
			log.Info("web interface listening", "addr", cfg.HTTPAddr)
			if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("web server: %w", err)
			}
		}()
	} else {
		log.Info("web interface disabled", "hint", config.EnvHTTPAddr+" not set")
	}

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errc:
		return err
	}

	if srv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			log.Warn("web server shutdown", "err", err)
		}
	}
	log.Info("stopped")
	return nil
}
