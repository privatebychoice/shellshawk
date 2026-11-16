// Package events is a small in-process publish/subscribe bus. Core services
// publish account events; plugins subscribe, e.g. to remove a user's data
// when the account is erased (docs/DESIGN.md §3.1, §5.2).
package events

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
)

// Core topics.
const (
	UserRegistered = "user.registered"
	UserApproved   = "user.approved"
	UserRejected   = "user.rejected" // account deleted before approval
	UserLocked     = "user.locked"
	UserUnlocked   = "user.unlocked"
	// UserErased is published when an account's grace period ends, before
	// the account becomes an anonymous tombstone. Plugins must remove or
	// detach the member's data; DeleteContent says whether the member
	// asked for their posts and chat lines to be deleted (true) or kept,
	// credited to the tombstone (false). A failing handler postpones the
	// erasure to the next run.
	UserErased = "user.erased"
)

// Event is one published event.
type Event struct {
	Topic  string
	UserID int64 // the account the event is about, if any
	Actor  int64 // who caused it (0 = system)
	// DeleteContent is set for UserErased only.
	DeleteContent bool
}

// Handler handles an event. Errors are collected and logged; they do not
// stop other handlers.
type Handler func(ctx context.Context, e Event) error

// Bus delivers events synchronously, in subscription order.
type Bus struct {
	mu   sync.RWMutex
	subs map[string][]named
	log  *slog.Logger
}

type named struct {
	name string
	h    Handler
}

// New returns an empty bus.
func New(log *slog.Logger) *Bus {
	return &Bus{subs: map[string][]named{}, log: log.With("component", "events")}
}

// Subscribe registers h for topic. name identifies the subscriber in logs.
func (b *Bus) Subscribe(topic, name string, h Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs[topic] = append(b.subs[topic], named{name, h})
}

// Publish calls every handler for e.Topic. A panicking handler is recovered
// and reported as an error, so one subscriber cannot break the publisher.
func (b *Bus) Publish(ctx context.Context, e Event) error {
	b.mu.RLock()
	subs := append([]named(nil), b.subs[e.Topic]...)
	b.mu.RUnlock()

	var errs []error
	for _, s := range subs {
		if err := call(ctx, s.h, e); err != nil {
			b.log.Error("event handler failed", "topic", e.Topic, "subscriber", s.name, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", s.name, err))
		}
	}
	b.log.Debug("event published", "topic", e.Topic, "subscribers", len(subs))
	return errors.Join(errs...)
}

func call(ctx context.Context, h Handler, e Event) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return h(ctx, e)
}
