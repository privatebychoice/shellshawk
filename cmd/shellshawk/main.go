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

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/bbs"
	"go.privatebychoice.com/shellshawk/internal/config"
	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
	"go.privatebychoice.com/shellshawk/internal/linkgrade"
	"go.privatebychoice.com/shellshawk/internal/logging"
	"go.privatebychoice.com/shellshawk/internal/menu"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/plugins/chat"
	"go.privatebychoice.com/shellshawk/internal/plugins/conferences"
	"go.privatebychoice.com/shellshawk/internal/plugins/contacts"
	"go.privatebychoice.com/shellshawk/internal/plugins/messages"
	"go.privatebychoice.com/shellshawk/internal/plugins/motd"
	"go.privatebychoice.com/shellshawk/internal/plugins/polls"
	"go.privatebychoice.com/shellshawk/internal/plugins/userlist"
	"go.privatebychoice.com/shellshawk/internal/plugins/wall"
	"go.privatebychoice.com/shellshawk/internal/prefs"
	"go.privatebychoice.com/shellshawk/internal/presence"
	"go.privatebychoice.com/shellshawk/internal/privacy"
	"go.privatebychoice.com/shellshawk/internal/sessions"
	"go.privatebychoice.com/shellshawk/internal/settings"
	"go.privatebychoice.com/shellshawk/internal/sftpd"
	"go.privatebychoice.com/shellshawk/internal/sshd"
	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/theme"
	"go.privatebychoice.com/shellshawk/internal/version"
	"go.privatebychoice.com/shellshawk/internal/web"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

const (
	shutdownTimeout    = 10 * time.Second
	auditPurgeInterval = 24 * time.Hour
	erasureInterval    = time.Hour
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
	prefs *prefs.Service
	grade *linkgrade.Grader

	plugins  *plugin.Registry
	presence *presence.Tracker
	privacy  *privacy.Service
	bus      *events.Bus
}

// installedPlugins are compiled into this build (docs/DESIGN.md §12).
func installedPlugins() []plugin.Plugin {
	c := contacts.New()
	m := messages.New(c)
	pl := polls.New()
	ch := chat.New()
	return []plugin.Plugin{c, m, pl, userlist.New(c, m), ch, conferences.New(pl, ch), motd.New(), wall.New()}
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
	themes, err := theme.Builtin()
	if err != nil {
		return err
	}
	grader, err := linkgrade.New(cfg.PBCDataFile, cfg.FirstPartyDomains)
	if err != nil {
		return err
	}
	log.Info("link grading ready", "local_dataset", cfg.PBCDataFile != "", "first_party_domains", len(cfg.FirstPartyDomains))
	perms := perm.NewService(db, perm.NewRegistry(), nil, log)
	a := &app{
		cfg: cfg, log: log, db: db, perms: perms,
		auth:  auth.NewService(db, perms, cfg.InviteUser, nil, log),
		prefs: prefs.NewService(db, themes, nil),
		grade: grader,
	}
	bus := events.New(log)
	a.bus = bus
	a.auth.SetPublisher(bus)
	a.presence = presence.New(nil)
	a.privacy = privacy.NewService(db, a.auth, perms, time.Duration(cfg.ErasureGraceDays)*24*time.Hour, nil, log)
	installed := installedPlugins()
	for _, p := range installed {
		if fc, ok := p.(privacy.FriendChecker); ok {
			a.privacy.SetFriends(fc)
		}
	}
	plugins, err := plugin.Load(ctx, plugin.Deps{DB: db, Perms: perms, Auth: a.auth, Events: bus, Presence: a.presence, Privacy: a.privacy, Log: log}, installed...)
	if err != nil {
		return err
	}
	a.plugins = plugins

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

	siteSettings := settings.NewService(a.db, nil, log)
	conns := presence.NewConns(nil)
	handler := &bbs.Handler{
		Auth: a.auth, Settings: siteSettings, Grader: a.grade, Perms: a.perms, Prefs: a.prefs,
		Menu: menu.NewService(a.db, a.perms, nil, log), Plugins: a.plugins, Presence: a.presence, Privacy: a.privacy,
		Sessions: sessions.NewService(a.db, conns, nil, log), Log: log,
	}
	var webSessions *websess.Service
	if cfg.WebEnabled() {
		webSessions = websess.NewService(a.db, a.auth, nil, log)
		handler.WebLogin = webSessions
	}
	if err := handler.Menu.Seed(ctx, handler.MenuDefaults()); err != nil {
		return err
	}

	go a.purgeAuditLog(ctx)
	go a.runErasures(ctx)

	errc := make(chan error, 2)

	var sshSrv *sshd.Server
	var hostKeyFP string
	if cfg.SSHEnabled() {
		hostKey, err := sshd.LoadOrCreateHostKey(cfg.SSHHostKeyPath, log)
		if err != nil {
			return err
		}
		hostKeyFP = ssh.FingerprintSHA256(hostKey.PublicKey())
		sftpSrv, err := sftpd.New(a.auth, a.perms, cfg.SFTPMaxUpload, log,
			append([]sftpd.Mount{sftpd.MeMount(a.auth, a.perms, append([]export.Source{a.privacy.ExportSource()}, a.plugins.ExportSources()...)...)},
				a.plugins.Mounts()...)...)
		if err != nil {
			return err
		}
		sshSrv, err = sshd.New(sshd.Config{
			Addr:     cfg.SSHAddr,
			HostKey:  hostKey,
			Auth:     auth.NewSSHAuthenticator(a.auth),
			Handler:  handler,
			SFTP:     sftpSrv,
			MaxConns: cfg.SSHMaxConns,
			Limits: func(ctx context.Context) sshd.Limits {
				l := siteSettings.ConnLimits(ctx)
				return sshd.Limits{IdleTimeout: time.Duration(l.IdleMinutes) * time.Minute, MaxPerUser: l.MaxPerUser}
			},
			Conns: conns,
			Log:   log,
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
		site, err := web.New(web.Config{
			Log: log, SiteName: siteSettings.BBSName, Auth: a.auth, Perms: a.perms, Sessions: webSessions,
			Prefs: a.prefs, Themes: a.prefs.Themes(), Plugins: a.plugins, Grader: a.grade,
			SSHAddress: cfg.PublicSSHAddress, HostKeyFingerprint: hostKeyFP, InviteUser: cfg.InviteUser,
			InsecureCookies: cfg.HTTPInsecureCookies, PrivacyPolicyFile: cfg.PrivacyPolicyFile,
			ChatDays: chat.DefaultRetention, AuditDays: cfg.AuditRetentionDays, GraceDays: cfg.ErasureGraceDays,
		})
		if err != nil {
			return err
		}
		if cfg.HTTPInsecureCookies {
			log.Warn("insecure web cookies enabled: use only for local testing over plain HTTP")
		}
		webSrv = web.NewHTTPServer(cfg.HTTPAddr, site.Handler(), log)
		webSrv.RegisterOnShutdown(site.CloseStreams) // live streams would hold up a graceful shutdown
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

// runErasures erases accounts whose grace period has ended, at startup and
// then hourly.
func (a *app) runErasures(ctx context.Context) {
	t := time.NewTicker(erasureInterval)
	defer t.Stop()
	for {
		n, err := a.privacy.RunDue(ctx, a.bus)
		switch {
		case err != nil && ctx.Err() == nil:
			a.log.Error("erasure run failed", "err", err)
		case n > 0:
			a.log.Info("accounts erased", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
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
