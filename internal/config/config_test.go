package config

import (
	"log/slog"
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
			want: Config{DBPath: "bbs.db", LogLevel: slog.LevelInfo, LogFormat: LogFormatText},
		},
		{
			name: "all set",
			env: map[string]string{
				EnvDBPath: " bbs.db ", EnvLogLevel: "debug", EnvLogFormat: "JSON", EnvHTTPAddr: "127.0.0.1:8080",
			},
			want: Config{DBPath: "bbs.db", LogLevel: slog.LevelDebug, LogFormat: LogFormatJSON, HTTPAddr: "127.0.0.1:8080"},
		},
		{
			name: "listen on all interfaces",
			env:  map[string]string{EnvDBPath: "bbs.db", EnvHTTPAddr: ":8080"},
			want: Config{DBPath: "bbs.db", LogLevel: slog.LevelInfo, LogFormat: LogFormatText, HTTPAddr: ":8080"},
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
			if got != tt.want {
				t.Errorf("Load() = %+v, want %+v", got, tt.want)
			}
			if got.WebEnabled() != (tt.want.HTTPAddr != "") {
				t.Errorf("WebEnabled() = %v", got.WebEnabled())
			}
		})
	}
}
