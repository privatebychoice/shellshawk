package web

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/version"
)

func TestRoutes(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		target     string
		wantStatus int
	}{
		{"version GET", http.MethodGet, "/version", http.StatusOK},
		{"version HEAD", http.MethodHead, "/version", http.StatusOK},
		{"version POST rejected", http.MethodPost, "/version", http.StatusMethodNotAllowed},
		{"unknown path", http.MethodGet, "/nope", http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logBuf bytes.Buffer
			h := NewHandler(slog.New(slog.NewTextHandler(&logBuf, nil)))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.target, nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			id := rec.Header().Get("X-Request-ID")
			if len(id) != 16 {
				t.Errorf("X-Request-ID = %q, want 16 hex chars", id)
			}
			if !strings.Contains(logBuf.String(), "request_id="+id) {
				t.Errorf("access log missing request id: %s", logBuf.String())
			}
		})
	}
}

func TestVersionBody(t *testing.T) {
	h := NewHandler(slog.New(slog.DiscardHandler))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/version", nil))

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	var got version.Info
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != version.Get() {
		t.Errorf("body = %+v, want %+v", got, version.Get())
	}
}

func TestAccessLogOmitsQueryAndClientData(t *testing.T) {
	var logBuf bytes.Buffer
	h := NewHandler(slog.New(slog.NewTextHandler(&logBuf, nil)))
	req := httptest.NewRequest(http.MethodGet, "/version?token=secret", nil)
	req.Header.Set("User-Agent", "agent-marker")
	h.ServeHTTP(httptest.NewRecorder(), req)

	for _, leak := range []string{"secret", "agent-marker", req.RemoteAddr} {
		if strings.Contains(logBuf.String(), leak) {
			t.Errorf("access log contains %q: %s", leak, logBuf.String())
		}
	}
}
