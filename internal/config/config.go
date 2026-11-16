// Package config loads shellshawk configuration from environment variables.
//
// Nothing environment-specific (paths, addresses, ports) has a built-in
// default: required values must be set explicitly, and optional front doors
// (such as the web interface) stay disabled until configured.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Defaults for optional settings.
const (
	DefaultSSHMaxConns        = 100
	DefaultInviteUser         = "new"
	DefaultAuditRetentionDays = 365
)

// domainPattern is a deliberately simple hostname check for first-party
// domains: dot-separated labels of letters, digits and hyphens.
var domainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// inviteUserPattern matches the username rules in internal/auth.
var inviteUserPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{2,31}$`)

// Environment variable names.
const (
	EnvDBPath    = "SHELLSHAWK_DB_PATH"
	EnvLogLevel  = "SHELLSHAWK_LOG_LEVEL"
	EnvLogFormat = "SHELLSHAWK_LOG_FORMAT"
	EnvHTTPAddr  = "SHELLSHAWK_HTTP_ADDR"

	EnvSSHAddr     = "SHELLSHAWK_SSH_ADDR"
	EnvSSHHostKey  = "SHELLSHAWK_SSH_HOST_KEY"
	EnvSSHMaxConns = "SHELLSHAWK_SSH_MAX_CONNS"

	EnvInviteUser         = "SHELLSHAWK_INVITE_USER"
	EnvAuditRetentionDays = "SHELLSHAWK_AUDIT_RETENTION_DAYS"

	EnvPBCDataFile       = "SHELLSHAWK_PBC_DATA_FILE"
	EnvFirstPartyDomains = "SHELLSHAWK_FIRST_PARTY_DOMAINS"
)

// Log output formats.
const (
	LogFormatText = "text"
	LogFormatJSON = "json"
)

// Config is the validated runtime configuration.
type Config struct {
	// DBPath is the SQLite database file. Required.
	DBPath string
	// LogLevel is the minimum level logged. Default: INFO.
	LogLevel slog.Level
	// LogFormat is "text" or "json". Default: text.
	LogFormat string
	// HTTPAddr is the host:port the web interface listens on. Empty disables
	// the web interface.
	HTTPAddr string
	// SSHAddr is the host:port the SSH server listens on. Empty disables SSH.
	SSHAddr string
	// SSHHostKeyPath is the Ed25519 host key file, created on first run if
	// missing. Required when SSH is enabled.
	SSHHostKeyPath string
	// SSHMaxConns caps concurrent SSH connections. Default: 100.
	SSHMaxConns int
	// InviteUser is the SSH login name for invite-code registration.
	// Default: "new".
	InviteUser string
	// AuditRetentionDays is how long audit log entries are kept. Default: 365.
	AuditRetentionDays int
	// PBCDataFile is an optional local pbc-classification dataset merged
	// over the library's built-in data.
	PBCDataFile string
	// FirstPartyDomains are the operator's own sites, graded as first-party.
	FirstPartyDomains []string
}

// SSHEnabled reports whether the SSH server should be started.
func (c Config) SSHEnabled() bool { return c.SSHAddr != "" }

// WebEnabled reports whether the web interface should be started.
func (c Config) WebEnabled() bool { return c.HTTPAddr != "" }

// Load reads configuration using getenv (normally os.Getenv) and validates it.
// All problems are reported together so a misconfigured deploy can be fixed in
// one pass.
func Load(getenv func(string) string) (Config, error) {
	var errs []error
	cfg := Config{
		DBPath:    strings.TrimSpace(getenv(EnvDBPath)),
		LogLevel:  slog.LevelInfo,
		LogFormat: LogFormatText,
		HTTPAddr:  strings.TrimSpace(getenv(EnvHTTPAddr)),

		SSHAddr:        strings.TrimSpace(getenv(EnvSSHAddr)),
		SSHHostKeyPath: strings.TrimSpace(getenv(EnvSSHHostKey)),
		SSHMaxConns:    DefaultSSHMaxConns,

		InviteUser:         DefaultInviteUser,
		AuditRetentionDays: DefaultAuditRetentionDays,
	}

	if cfg.DBPath == "" {
		errs = append(errs, fmt.Errorf("%s is required", EnvDBPath))
	}

	if v := strings.TrimSpace(getenv(EnvLogLevel)); v != "" {
		if err := cfg.LogLevel.UnmarshalText([]byte(v)); err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid level %q (want DEBUG, INFO, WARN or ERROR)", EnvLogLevel, v))
		}
	}

	if v := strings.ToLower(strings.TrimSpace(getenv(EnvLogFormat))); v != "" {
		switch v {
		case LogFormatText, LogFormatJSON:
			cfg.LogFormat = v
		default:
			errs = append(errs, fmt.Errorf("%s: invalid format %q (want text or json)", EnvLogFormat, v))
		}
	}

	if cfg.HTTPAddr != "" && !validAddr(cfg.HTTPAddr) {
		errs = append(errs, fmt.Errorf("%s: invalid address %q (want host:port)", EnvHTTPAddr, cfg.HTTPAddr))
	}

	if cfg.SSHAddr != "" {
		if !validAddr(cfg.SSHAddr) {
			errs = append(errs, fmt.Errorf("%s: invalid address %q (want host:port)", EnvSSHAddr, cfg.SSHAddr))
		}
		if cfg.SSHHostKeyPath == "" {
			errs = append(errs, fmt.Errorf("%s is required when %s is set", EnvSSHHostKey, EnvSSHAddr))
		}
	}

	if v := strings.TrimSpace(getenv(EnvSSHMaxConns)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			errs = append(errs, fmt.Errorf("%s: invalid value %q (want a positive integer)", EnvSSHMaxConns, v))
		} else {
			cfg.SSHMaxConns = n
		}
	}

	if v := strings.ToLower(strings.TrimSpace(getenv(EnvInviteUser))); v != "" {
		if inviteUserPattern.MatchString(v) {
			cfg.InviteUser = v
		} else {
			errs = append(errs, fmt.Errorf("%s: invalid name %q (3-32 lowercase letters, digits, '_' or '-', starting with a letter)", EnvInviteUser, v))
		}
	}

	if v := strings.TrimSpace(getenv(EnvAuditRetentionDays)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			errs = append(errs, fmt.Errorf("%s: invalid value %q (want a positive number of days)", EnvAuditRetentionDays, v))
		} else {
			cfg.AuditRetentionDays = n
		}
	}

	cfg.PBCDataFile = strings.TrimSpace(getenv(EnvPBCDataFile))

	if v := strings.TrimSpace(getenv(EnvFirstPartyDomains)); v != "" {
		for _, d := range strings.Split(v, ",") {
			d = strings.ToLower(strings.TrimSpace(d))
			if d == "" {
				continue
			}
			if !domainPattern.MatchString(d) {
				errs = append(errs, fmt.Errorf("%s: invalid domain %q", EnvFirstPartyDomains, d))
				continue
			}
			cfg.FirstPartyDomains = append(cfg.FirstPartyDomains, d)
		}
	}

	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validAddr(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	return err == nil && port != ""
}
