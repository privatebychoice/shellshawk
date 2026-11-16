package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		level    slog.Level
		format   string
		wantJSON bool
		wantInfo bool // whether an INFO record is emitted
	}{
		{"text info", slog.LevelInfo, "text", false, true},
		{"json info", slog.LevelInfo, "json", true, true},
		{"unknown format falls back to text", slog.LevelInfo, "xml", false, true},
		{"warn level filters info", slog.LevelWarn, "text", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			New(&buf, tt.level, tt.format).Info("hello", "k", "v")
			out := buf.String()
			if (out != "") != tt.wantInfo {
				t.Fatalf("output = %q, wantInfo %v", out, tt.wantInfo)
			}
			if !tt.wantInfo {
				return
			}
			isJSON := json.Valid(bytes.TrimSpace(buf.Bytes()))
			if isJSON != tt.wantJSON {
				t.Errorf("json output = %v, want %v: %q", isJSON, tt.wantJSON, out)
			}
			if !strings.Contains(out, "hello") {
				t.Errorf("message missing: %q", out)
			}
		})
	}
}
