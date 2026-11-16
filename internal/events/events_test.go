package events

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

func TestBus(t *testing.T) {
	b := New(slog.New(slog.DiscardHandler))
	var got []string
	b.Subscribe(UserApproved, "first", func(_ context.Context, e Event) error {
		got = append(got, "first")
		return nil
	})
	b.Subscribe(UserApproved, "failing", func(context.Context, Event) error { return errors.New("boom") })
	b.Subscribe(UserApproved, "panicking", func(context.Context, Event) error { panic("bad plugin") })
	b.Subscribe(UserApproved, "last", func(_ context.Context, e Event) error {
		if e.UserID != 7 {
			t.Errorf("payload = %+v", e)
		}
		got = append(got, "last")
		return nil
	})
	b.Subscribe(UserLocked, "other", func(context.Context, Event) error { got = append(got, "wrong topic"); return nil })

	err := b.Publish(context.Background(), Event{Topic: UserApproved, UserID: 7})
	if err == nil {
		t.Fatal("errors from handlers not reported")
	}
	if len(got) != 2 || got[0] != "first" || got[1] != "last" {
		t.Errorf("handlers called = %v; a failing or panicking handler must not stop the rest", got)
	}
	if err := b.Publish(context.Background(), Event{Topic: "nobody.listens"}); err != nil {
		t.Errorf("no subscribers: %v", err)
	}
}
