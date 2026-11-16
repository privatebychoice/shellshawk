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
			want: Config{DBPath: "bbs.db", LogLevel: slog.LevelInfo, LogFormat: LogFormatText, SSHMaxConns: DefaultSSHMaxConns, InviteUser: DefaultInviteUser, AuditRetentionDays: DefaultAuditRetentionDays},
		},
		{
			name: "all set",
			env: map[string]string{
				EnvDBPath: " bbs.db ", EnvLogLevel: "debug", EnvLogFormat: "JSON", EnvHTTPAddr: "127.0.0.1:8080",
				EnvSSHAddr: ":2222", EnvSSHHostKey: "host_key", EnvSSHMaxConns: "25",
				EnvInviteUser: "SignUp", EnvAuditRetentionDays: "90",
				EnvPBCDataFile: " /data/pbc.json ", EnvFirstPartyDomains: "Example.org, bbs.example.net,",
			},
			want: Config{
				DBPath: "bbs.db", LogLevel: slog.LevelDebug, LogFormat: LogFormatJSON, HTTPAddr: "127.0.0.1:8080",
				SSHAddr: ":2222", SSHHostKeyPath: "host_key", SSHMaxConns: 25,
				InviteUser: "signup", AuditRetentionDays: 90,
				PBCDataFile: "/data/pbc.json", FirstPartyDomains: []string{"example.org", "bbs.example.net"},
			},
		},
		{
			name: "listen on all interfaces",
			env:  map[string]string{EnvDBPath: "bbs.db", EnvHTTPAddr: ":8080"},
			want: Config{DBPath: "bbs.db", LogLevel: slog.LevelInfo, LogFormat: LogFormatText, HTTPAddr: ":8080", SSHMaxConns: DefaultSSHMaxConns, InviteUser: DefaultInviteUser, AuditRetentionDays: DefaultAuditRetentionDays},
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
