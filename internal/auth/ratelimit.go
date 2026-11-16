package auth

import (
	"sync"
	"time"
)

// Limiter counts failures per key in a fixed window and blocks a key once it
// reaches the limit, until the window expires. State is in memory only and
// never logged or persisted (keys may contain client IP addresses).
type Limiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	now     func() time.Time
	entries map[string]*limitEntry
}

type limitEntry struct {
	failures int
	start    time.Time
}

// maxLimiterEntries bounds memory. When exceeded, expired entries are pruned;
// if the table is still full, the oldest windows are dropped.
const maxLimiterEntries = 50_000

// NewLimiter allows max failures per key per window. now may be nil.
func NewLimiter(max int, window time.Duration, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{max: max, window: window, now: now, entries: map[string]*limitEntry{}}
}

// Blocked reports whether key has reached the failure limit.
func (l *Limiter) Blocked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[key]
	if !ok {
		return false
	}
	if l.now().Sub(e.start) >= l.window {
		delete(l.entries, key)
		return false
	}
	return e.failures >= l.max
}

// Fail records a failure for key.
func (l *Limiter) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e, ok := l.entries[key]
	if !ok || now.Sub(e.start) >= l.window {
		if !ok && len(l.entries) >= maxLimiterEntries {
			l.prune(now)
		}
		l.entries[key] = &limitEntry{failures: 1, start: now}
		return
	}
	e.failures++
}

// Reset clears key, e.g. after a successful login.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// prune removes expired entries, then (if still at capacity) the oldest
// half. Called with l.mu held.
func (l *Limiter) prune(now time.Time) {
	for k, e := range l.entries {
		if now.Sub(e.start) >= l.window {
			delete(l.entries, k)
		}
	}
	if len(l.entries) < maxLimiterEntries {
		return
	}
	cutoff := now.Add(-l.window / 2)
	for k, e := range l.entries {
		if e.start.Before(cutoff) {
			delete(l.entries, k)
		}
	}
}
