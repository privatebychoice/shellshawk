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
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Defaults for optional settings.
const (
	DefaultSSHMaxConns        = 100
	DefaultSFTPMaxUpload      = 1 << 20  // 1 MiB
	MaxSFTPMaxUpload          = 64 << 20 // uploads are buffered in memory
	DefaultInviteUser         = "new"
	DefaultAuditRetentionDays = 365
	DefaultErasureGraceDays   = 14
	MaxErasureGraceDays       = 365
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

	EnvPublicSSHAddress    = "SHELLSHAWK_PUBLIC_SSH_ADDRESS"
	EnvHTTPInsecureCookies = "SHELLSHAWK_HTTP_INSECURE_COOKIES"
	EnvHTTPTrustedProxies  = "SHELLSHAWK_HTTP_TRUSTED_PROXIES"
	EnvPrivacyPolicyFile   = "SHELLSHAWK_PRIVACY_POLICY_FILE"

	EnvSSHAddr       = "SHELLSHAWK_SSH_ADDR"
	EnvSSHHostKey    = "SHELLSHAWK_SSH_HOST_KEY"
	EnvSSHMaxConns   = "SHELLSHAWK_SSH_MAX_CONNS"
	EnvSFTPMaxUpload = "SHELLSHAWK_SFTP_MAX_UPLOAD_BYTES"

	EnvInviteUser         = "SHELLSHAWK_INVITE_USER"
	EnvAuditRetentionDays = "SHELLSHAWK_AUDIT_RETENTION_DAYS"
	EnvErasureGraceDays   = "SHELLSHAWK_ERASURE_GRACE_DAYS"

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
	// PublicSSHAddress is the host:port members use to connect, shown on
	// the web start page (optional).
	PublicSSHAddress string
	// HTTPInsecureCookies drops the Secure cookie attribute and HSTS, for
	// local testing over plain HTTP only.
	HTTPInsecureCookies bool
	// HTTPTrustedProxies are the reverse proxies in front of the web
	// interface. Requests from them have the client's address taken from
	// X-Forwarded-For; any other request's own address is used.
	HTTPTrustedProxies []netip.Prefix
	// PrivacyPolicyFile replaces the built-in privacy policy (markdown).
	PrivacyPolicyFile string
	// SSHAddr is the host:port the SSH server listens on. Empty disables SSH.
	SSHAddr string
	// SSHHostKeyPath is the Ed25519 host key file, created on first run if
	// missing. Required when SSH is enabled.
	SSHHostKeyPath string
	// SSHMaxConns caps concurrent SSH connections. Default: 100.
	SSHMaxConns int
	// SFTPMaxUpload is the largest file accepted over SFTP, in bytes.
	SFTPMaxUpload int64
	// InviteUser is the SSH login name for invite-code registration.
	// Default: "new".
	InviteUser string
	// AuditRetentionDays is how long audit log entries are kept. Default: 365.
	AuditRetentionDays int
	// ErasureGraceDays is how long an erasure request waits before the
	// account is erased (0 = at the next run). Default: 14.
	ErasureGraceDays int
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

// parseAddrOrPrefix reads "192.0.2.1", "2001:db8::1" or a network such as
// "10.0.0.0/8", returning a single address as a one-address network.
func parseAddrOrPrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

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
		SFTPMaxUpload:  DefaultSFTPMaxUpload,

		InviteUser:         DefaultInviteUser,
		AuditRetentionDays: DefaultAuditRetentionDays,
		ErasureGraceDays:   DefaultErasureGraceDays,
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

	if v := strings.TrimSpace(getenv(EnvErasureGraceDays)); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > MaxErasureGraceDays {
			errs = append(errs, fmt.Errorf("%s: invalid value %q (want 0 to %d days)", EnvErasureGraceDays, v, MaxErasureGraceDays))
		} else {
			cfg.ErasureGraceDays = n
		}
	}

	if v := strings.TrimSpace(getenv(EnvSFTPMaxUpload)); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 || n > MaxSFTPMaxUpload {
			errs = append(errs, fmt.Errorf("%s: invalid value %q (want 1 to %d)", EnvSFTPMaxUpload, v, MaxSFTPMaxUpload))
		} else {
			cfg.SFTPMaxUpload = n
		}
	}

	cfg.PBCDataFile = strings.TrimSpace(getenv(EnvPBCDataFile))
	cfg.PrivacyPolicyFile = strings.TrimSpace(getenv(EnvPrivacyPolicyFile))

	if v := strings.TrimSpace(getenv(EnvPublicSSHAddress)); v != "" {
		if host, port, err := net.SplitHostPort(v); err != nil || host == "" || port == "" {
			errs = append(errs, fmt.Errorf("%s: invalid address %q (want host:port)", EnvPublicSSHAddress, v))
		} else {
			cfg.PublicSSHAddress = v
		}
	}

	if v := strings.TrimSpace(getenv(EnvHTTPInsecureCookies)); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid value %q (want true or false)", EnvHTTPInsecureCookies, v))
		}
		cfg.HTTPInsecureCookies = b
	}

	if v := strings.TrimSpace(getenv(EnvHTTPTrustedProxies)); v != "" {
		for _, item := range strings.Split(v, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			p, err := parseAddrOrPrefix(item)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: invalid address or network %q", EnvHTTPTrustedProxies, item))
				continue
			}
			cfg.HTTPTrustedProxies = append(cfg.HTTPTrustedProxies, p)
		}
	}

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
