// Package web serves the optional HTTP interface.
//
// Stage 1 provides only the /version endpoint and the shared middleware
// (request IDs, access logging). Pages, GPC, CSP and login arrive in later
// stages (docs/DESIGN.md §11).
package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"go.privatebychoice.com/shellshawk/internal/version"
)

// Server-side timeouts. They bound slow or idle clients so they can't hold
// connections open indefinitely.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
)

// NewServer returns an http.Server for addr with all routes and middleware.
func NewServer(addr string, log *slog.Logger) *http.Server {
	log = log.With("component", "web")
	return &http.Server{
		Addr:              addr,
		Handler:           NewHandler(log),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// NewHandler returns the root handler with middleware applied.
func NewHandler(log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /version", handleVersion) // GET also matches HEAD
	return withRequestLog(log, mux)
}

func handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(version.Get()); err != nil {
		LoggerFrom(r.Context()).Warn("write /version response", "err", err)
	}
}

type ctxKey struct{}

// LoggerFrom returns the request-scoped logger (carrying request_id), or the
// default logger outside a request.
func LoggerFrom(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKey{}).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

// statusRecorder captures the response status for the access log.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// withRequestLog assigns each request a random ID (returned in X-Request-ID)
// and writes one access-log line per request.
//
// Privacy: the log records method, path (no query string), status and
// duration only — never client IPs, user agents, cookies or query values.
func withRequestLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := newRequestID()
		rl := log.With("request_id", id)
		w.Header().Set("X-Request-ID", id)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), ctxKey{}, rl)))

		level := slog.LevelInfo
		if rec.status >= 500 {
			level = slog.LevelError
		}
		rl.Log(r.Context(), level, "http request",
			"method", r.Method, "path", r.URL.Path, "status", rec.status,
			"duration_ms", time.Since(start).Milliseconds())
	})
}

func newRequestID() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never returns an error
	return hex.EncodeToString(b[:])
}
