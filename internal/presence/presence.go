// Package presence tracks which members have an interactive BBS session open.
// It is in memory only: nothing is stored, and a restart forgets everything.
package presence

import (
	"sync"
	"time"
)

// Tracker counts open sessions per member.
type Tracker struct {
	mu    sync.Mutex
	count map[int64]int
	since map[int64]time.Time
	now   func() time.Time
}

// New returns an empty tracker. now may be nil.
func New(now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	return &Tracker{count: map[int64]int{}, since: map[int64]time.Time{}, now: now}
}

// Enter records a session start and returns the function to call when it
// ends. Calling it more than once has no further effect.
func (t *Tracker) Enter(userID int64) (leave func()) {
	t.mu.Lock()
	if t.count[userID] == 0 {
		t.since[userID] = t.now()
	}
	t.count[userID]++
	t.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.count[userID]--; t.count[userID] <= 0 {
				delete(t.count, userID)
				delete(t.since, userID)
			}
		})
	}
}

// Online returns the members with a session open and when their earliest
// open session started.
func (t *Tracker) Online() map[int64]time.Time {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make(map[int64]time.Time, len(t.since))
	for id, s := range t.since {
		out[id] = s
	}
	return out
}

// IsOnline reports whether a member has a session open.
func (t *Tracker) IsOnline(userID int64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.count[userID] > 0
}
