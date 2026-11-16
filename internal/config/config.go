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
	"strings"
)

// Environment variable names.
const (
	EnvDBPath    = "SHELLSHAWK_DB_PATH"
	EnvLogLevel  = "SHELLSHAWK_LOG_LEVEL"
	EnvLogFormat = "SHELLSHAWK_LOG_FORMAT"
	EnvHTTPAddr  = "SHELLSHAWK_HTTP_ADDR"
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
}

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

	if cfg.HTTPAddr != "" {
		if _, port, err := net.SplitHostPort(cfg.HTTPAddr); err != nil || port == "" {
			errs = append(errs, fmt.Errorf("%s: invalid address %q (want host:port)", EnvHTTPAddr, cfg.HTTPAddr))
		}
	}

	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
