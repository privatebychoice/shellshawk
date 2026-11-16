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
	"strconv"
	"strings"
)

// DefaultSSHMaxConns is used when SHELLSHAWK_SSH_MAX_CONNS is unset.
const DefaultSSHMaxConns = 100

// Environment variable names.
const (
	EnvDBPath    = "SHELLSHAWK_DB_PATH"
	EnvLogLevel  = "SHELLSHAWK_LOG_LEVEL"
	EnvLogFormat = "SHELLSHAWK_LOG_FORMAT"
	EnvHTTPAddr  = "SHELLSHAWK_HTTP_ADDR"

	EnvSSHAddr     = "SHELLSHAWK_SSH_ADDR"
	EnvSSHHostKey  = "SHELLSHAWK_SSH_HOST_KEY"
	EnvSSHMaxConns = "SHELLSHAWK_SSH_MAX_CONNS"
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

	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validAddr(addr string) bool {
	_, port, err := net.SplitHostPort(addr)
	return err == nil && port != ""
}
