package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.privatebychoice.com/shellshawk/internal/plugin"
)

// Live streams (server-sent events) hold a connection open, so they get
// their own limits instead of the request timeouts.
const (
	maxStreamsPerUser = 4            // tabs a member may keep live at once
	streamWriteWait   = writeTimeout // per write, so a stalled client is dropped
)

// sessionRecheck is how soon a logout ends a stream (a variable for tests).
var sessionRecheck = 30 * time.Second

// streams tracks open streams so they can be limited per member and all
// ended when the server shuts down.
type streams struct {
	mu     sync.Mutex
	open   map[int64]int
	ctx    context.Context
	cancel context.CancelFunc
}

func newStreams() *streams {
	ctx, cancel := context.WithCancel(context.Background())
	return &streams{open: map[int64]int{}, ctx: ctx, cancel: cancel}
}

func (st *streams) acquire(user int64) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.open[user] >= maxStreamsPerUser {
		return false
	}
	st.open[user]++
	return true
}

func (st *streams) release(user int64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.open[user]--; st.open[user] <= 0 {
		delete(st.open, user)
	}
}

// CloseStreams ends every live stream. Register it with
// http.Server.RegisterOnShutdown so a graceful shutdown is not held up by
// open connections.
func (s *Server) CloseStreams() { s.streams.cancel() }

// streamWriter sets a fresh write deadline before each write, replacing the
// server's whole-response WriteTimeout, which would cut every stream.
type streamWriter struct {
	http.ResponseWriter
	rc *http.ResponseController
}

func (w streamWriter) Write(b []byte) (int, error) {
	_ = w.rc.SetWriteDeadline(time.Now().Add(streamWriteWait))
	return w.ResponseWriter.Write(b)
}

func (w streamWriter) Flush() { _ = w.rc.Flush() }

func (w streamWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// pluginStream serves a plugin's live stream to a logged-in member holding
// the route's permission. It answers with a status rather than a page or
// redirect, because the client is a script (EventSource), not a person.
func (s *Server) pluginStream(id string, route plugin.WebRoute) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log := LoggerFrom(r.Context())
		sess := sessionFrom(r)
		if sess == nil {
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		}
		set, err := s.cfg.Perms.Permissions(r.Context(), sess.UserID)
		if err != nil || !allowed(set, route.AnyOf) {
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
		if !s.streams.acquire(sess.UserID) {
			log.Info("live stream refused: too many open", "plugin", id, "user_id", sess.UserID)
			http.Error(w, "Too many live pages open", http.StatusTooManyRequests)
			return
		}
		defer s.streams.release(sess.UserID)

		rc := http.NewResponseController(w)
		// No read deadline: an expired one would cancel the request
		// context while the stream is idle.
		if err := rc.SetReadDeadline(time.Time{}); err != nil {
			log.Error("live stream unsupported", "plugin", id, "err", err)
			http.Error(w, "Live updates are unavailable", http.StatusInternalServerError)
			return
		}

		ctx, cancel := context.WithDeadline(r.Context(), sess.ExpiresAt)
		defer cancel()
		stop := context.AfterFunc(s.streams.ctx, cancel)
		defer stop()
		token := ""
		if c, err := r.Cookie(s.cookieName()); err == nil {
			token = c.Value
		}
		go s.watchSession(ctx, cancel, token)

		log.Info("live stream opened", "plugin", id, "user_id", sess.UserID)
		err = safeStream(route, streamWriter{ResponseWriter: w, rc: rc}, r.WithContext(ctx),
			webSession{s: s, user: sess.UserID, plugin: id, csrf: sess.CSRF})
		switch {
		case errors.Is(err, plugin.ErrWebNotFound):
			http.Error(w, "Not found", http.StatusNotFound)
		case err != nil && ctx.Err() == nil:
			log.Error("live stream failed", "plugin", id, "err", err)
		}
		log.Info("live stream closed", "plugin", id, "user_id", sess.UserID)
	})
}

// watchSession cancels a stream once its session is logged out or deleted.
func (s *Server) watchSession(ctx context.Context, cancel context.CancelFunc, token string) {
	t := time.NewTicker(sessionRecheck)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := s.cfg.Sessions.Lookup(ctx, token); err != nil {
				cancel()
				return
			}
		}
	}
}

func safeStream(route plugin.WebRoute, w http.ResponseWriter, r *http.Request, ws plugin.WebSession) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("panic: %v", rec)
		}
	}()
	return route.Stream(w, r, ws)
}
