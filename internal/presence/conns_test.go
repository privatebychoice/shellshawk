package presence

import (
	"errors"
	"testing"
	"time"
)

func TestConnsLimit(t *testing.T) {
	tests := []struct {
		name    string
		userID  int64
		max     int
		open    int // already open for this user
		wantErr error
	}{
		{"under the limit", 1, 2, 1, nil},
		{"at the limit", 1, 2, 2, ErrTooMany},
		{"no limit", 1, 0, 5, nil},
		{"registering is never limited", 0, 1, 3, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewConns(nil)
			for range tt.open {
				if _, err := r.Open(tt.userID, "member", 0, nil); err != nil {
					t.Fatal(err)
				}
			}
			r.Open(99, "member", 0, nil) // another member's connection never counts
			if _, err := r.Open(tt.userID, "member", tt.max, nil); !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestConnsLifecycle(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r := NewConns(func() time.Time { return now })
	var ended error
	a, _ := r.Open(1, "member", 0, func(cause error) { ended = cause })
	b, _ := r.Open(2, "pending", 0, nil)

	now = now.Add(time.Minute)
	a.Touch()
	doneT := a.Use(UseTerminal)
	a.Use(UseSFTP)
	list := r.List()
	if len(list) != 2 || list[0].ID != a.ID() || list[1].ID != b.ID() {
		t.Fatalf("list = %+v", list)
	}
	if got := list[0]; !got.LastActive.Equal(now) || got.Terminals != 1 || got.Transfers != 1 || got.Mode != "member" {
		t.Errorf("a = %+v", got)
	}
	doneT()
	doneT() // idempotent
	if got, _ := r.Get(a.ID()); got.Terminals != 0 {
		t.Errorf("terminals after done = %d", got.Terminals)
	}

	cause := &Disconnect{Message: "bye"}
	if !r.End(a.ID(), cause) || ended != cause {
		t.Errorf("End: ended = %v", ended)
	}
	a.Close()
	a.Close()
	if _, ok := r.Get(a.ID()); ok || r.End(a.ID(), cause) {
		t.Error("closed connection still listed")
	}
	if len(r.List()) != 1 {
		t.Errorf("list after close = %+v", r.List())
	}
}

func TestConnsEndUser(t *testing.T) {
	r := NewConns(nil)
	ended := map[uint64]error{}
	open := func(uid int64) *Conn {
		var c *Conn
		c, _ = r.Open(uid, "member", 0, func(cause error) { ended[c.ID()] = cause })
		return c
	}
	a1, a2, b, reg := open(1), open(1), open(2), open(0)
	cause := &Disconnect{Message: "locked"}
	if n := r.EndUser(1, cause); n != 2 {
		t.Errorf("ended %d connections, want 2", n)
	}
	if ended[a1.ID()] != cause || ended[a2.ID()] != cause || ended[b.ID()] != nil {
		t.Errorf("ended = %v", ended)
	}
	if n := r.EndUser(0, cause); n != 0 || ended[reg.ID()] != nil {
		t.Error("EndUser(0) ended registrations")
	}
}
