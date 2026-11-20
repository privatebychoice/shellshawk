package config

import (
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		want    Config
		wantErr []string // substrings expected in the error
	}{
		{
			name: "minimal",
			env:  map[string]string{EnvDBPath: "bbs.db"},
			want: Config{DBPath: "bbs.db", LogLevel: slog.LevelInfo, LogFormat: LogFormatText, SSHMaxConns: DefaultSSHMaxConns, SFTPMaxUpload: DefaultSFTPMaxUpload, InviteUser: DefaultInviteUser, AuditRetentionDays: DefaultAuditRetentionDays, ErasureGraceDays: DefaultErasureGraceDays},
		},
		{
			name: "all set",
			env: map[string]string{
				EnvDBPath: " bbs.db ", EnvLogLevel: "debug", EnvLogFormat: "JSON", EnvHTTPAddr: "127.0.0.1:8080",
				EnvSSHAddr: ":2222", EnvSSHHostKey: "host_key", EnvSSHMaxConns: "25",
				EnvInviteUser: "SignUp", EnvAuditRetentionDays: "90", EnvErasureGraceDays: "30",
				EnvSFTPMaxUpload:    "2048",
				EnvPublicSSHAddress: "bbs.example.net:22", EnvHTTPInsecureCookies: "true", EnvPrivacyPolicyFile: "/etc/policy.md",
				EnvPBCDataFile: " /data/pbc.json ", EnvFirstPartyDomains: "Example.org, bbs.example.net,",
			},
			want: Config{
				DBPath: "bbs.db", LogLevel: slog.LevelDebug, LogFormat: LogFormatJSON, HTTPAddr: "127.0.0.1:8080",
				SSHAddr: ":2222", SSHHostKeyPath: "host_key", SSHMaxConns: 25, SFTPMaxUpload: 2048,
				PublicSSHAddress: "bbs.example.net:22", HTTPInsecureCookies: true, PrivacyPolicyFile: "/etc/policy.md",
				InviteUser: "signup", AuditRetentionDays: 90, ErasureGraceDays: 30,
				PBCDataFile: "/data/pbc.json", FirstPartyDomains: []string{"example.org", "bbs.example.net"},
			},
		},
		{
			name: "listen on all interfaces",
			env:  map[string]string{EnvDBPath: "bbs.db", EnvHTTPAddr: ":8080"},
			want: Config{DBPath: "bbs.db", LogLevel: slog.LevelInfo, LogFormat: LogFormatText, HTTPAddr: ":8080", SSHMaxConns: DefaultSSHMaxConns, SFTPMaxUpload: DefaultSFTPMaxUpload, InviteUser: DefaultInviteUser, AuditRetentionDays: DefaultAuditRetentionDays, ErasureGraceDays: DefaultErasureGraceDays},
		},
		{
			name:    "missing db path",
			env:     map[string]string{},
			wantErr: []string{EnvDBPath},
		},
		{
			name:    "bad level",
			env:     map[string]string{EnvDBPath: "x", EnvLogLevel: "loud"},
			wantErr: []string{EnvLogLevel},
		},
		{
			name:    "bad format",
			env:     map[string]string{EnvDBPath: "x", EnvLogFormat: "xml"},
			wantErr: []string{EnvLogFormat},
		},
		{
			name:    "bad http addr",
			env:     map[string]string{EnvDBPath: "x", EnvHTTPAddr: "8080"},
			wantErr: []string{EnvHTTPAddr},
		},
		{
			name:    "empty port",
			env:     map[string]string{EnvDBPath: "x", EnvHTTPAddr: "localhost:"},
			wantErr: []string{EnvHTTPAddr},
		},
		{
			name:    "ssh without host key",
			env:     map[string]string{EnvDBPath: "x", EnvSSHAddr: ":2222"},
			wantErr: []string{EnvSSHHostKey},
		},
		{
			name:    "bad ssh addr",
			env:     map[string]string{EnvDBPath: "x", EnvSSHAddr: "2222", EnvSSHHostKey: "k"},
			wantErr: []string{EnvSSHAddr},
		},
		{
			name:    "bad max conns",
			env:     map[string]string{EnvDBPath: "x", EnvSSHMaxConns: "0"},
			wantErr: []string{EnvSSHMaxConns},
		},
		{
			name:    "non-numeric max conns",
			env:     map[string]string{EnvDBPath: "x", EnvSSHMaxConns: "lots"},
			wantErr: []string{EnvSSHMaxConns},
		},
		{
			name:    "bad invite user",
			env:     map[string]string{EnvDBPath: "x", EnvInviteUser: "a b"},
			wantErr: []string{EnvInviteUser},
		},
		{
			name:    "bad retention",
			env:     map[string]string{EnvDBPath: "x", EnvAuditRetentionDays: "-1"},
			wantErr: []string{EnvAuditRetentionDays},
		},
		{
			name:    "bad first-party domain",
			env:     map[string]string{EnvDBPath: "x", EnvFirstPartyDomains: "example.org, https://bad"},
			wantErr: []string{EnvFirstPartyDomains},
		},
		{
			name:    "upload limit too large",
			env:     map[string]string{EnvDBPath: "x", EnvSFTPMaxUpload: "999999999999"},
			wantErr: []string{EnvSFTPMaxUpload},
		},
		{
			name:    "grace too long",
			env:     map[string]string{EnvDBPath: "x", EnvErasureGraceDays: "400"},
			wantErr: []string{EnvErasureGraceDays},
		},
		{
			name:    "bad public ssh address",
			env:     map[string]string{EnvDBPath: "x", EnvPublicSSHAddress: "bbs.example.net"},
			wantErr: []string{EnvPublicSSHAddress},
		},
		{
			name:    "bad cookie flag",
			env:     map[string]string{EnvDBPath: "x", EnvHTTPInsecureCookies: "maybe"},
			wantErr: []string{EnvHTTPInsecureCookies},
		},
		{
			name:    "bad trusted proxy",
			env:     map[string]string{EnvDBPath: "x", EnvHTTPTrustedProxies: "10.0.0.1, proxy.example.net"},
			wantErr: []string{EnvHTTPTrustedProxies},
		},
		{
			name:    "errors are reported together",
			env:     map[string]string{EnvLogLevel: "loud", EnvLogFormat: "xml"},
			wantErr: []string{EnvDBPath, EnvLogLevel, EnvLogFormat},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(env(tt.env))
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatalf("Load() error = nil, want error mentioning %v", tt.wantErr)
				}
				for _, s := range tt.wantErr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("Load() error %q does not mention %q", err, s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
			if got.WebEnabled() != (tt.want.HTTPAddr != "") {
				t.Errorf("WebEnabled() = %v", got.WebEnabled())
			}
			if got.SSHEnabled() != (tt.want.SSHAddr != "") {
				t.Errorf("SSHEnabled() = %v", got.SSHEnabled())
			}
		})
	}
}

func TestTrustedProxies(t *testing.T) {
	got, err := Load(env(map[string]string{EnvDBPath: "x", EnvHTTPTrustedProxies: " 192.0.2.10, 10.1.2.3/8,,::ffff:198.51.100.1, 2001:db8::/32 "}))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.0.2.10/32", "10.0.0.0/8", "198.51.100.1/32", "2001:db8::/32"}
	if len(got.HTTPTrustedProxies) != len(want) {
		t.Fatalf("proxies = %v, want %v", got.HTTPTrustedProxies, want)
	}
	for i, p := range got.HTTPTrustedProxies {
		if p.String() != want[i] {
			t.Errorf("proxy %d = %s, want %s", i, p, want[i])
		}
	}
}

func TestSFTPMaxUploadMemory(t *testing.T) {
	tests := []struct {
		name  string
		env   map[string]string
		want  int64
		wantE bool
	}{
		{"unset: the default (0, meaning 16 x the upload limit)", nil, 0, false},
		{"set", map[string]string{EnvSFTPMaxUploadMemory: "33554432"}, 32 << 20, false},
		{"below the upload limit", map[string]string{EnvSFTPMaxUpload: "2097152", EnvSFTPMaxUploadMemory: "1048576"}, 0, true},
		{"too high", map[string]string{EnvSFTPMaxUploadMemory: "99999999999999"}, 0, true},
		{"not a number", map[string]string{EnvSFTPMaxUploadMemory: "lots"}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := map[string]string{EnvDBPath: "x"}
			for k, v := range tt.env {
				e[k] = v
			}
			got, err := Load(env(e))
			if (err != nil) != tt.wantE {
				t.Fatalf("err = %v, want error %v", err, tt.wantE)
			}
			if err == nil && got.SFTPMaxUploadMemory != tt.want {
				t.Errorf("SFTPMaxUploadMemory = %d, want %d", got.SFTPMaxUploadMemory, tt.want)
			}
		})
	}
}
