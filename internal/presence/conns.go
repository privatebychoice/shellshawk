package presence

import (
	"cmp"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// ErrTooMany is returned by Conns.Open when the member already has the most
// connections allowed.
var ErrTooMany = errors.New("presence: too many connections for this account")

// Disconnect is the cause given when the server ends a connection on
// purpose, for example after a period without activity or when a moderator
// ends it. Its message is written to the member's terminal, so it must be a
// complete sentence meant for them.
type Disconnect struct{ Message string }

func (d *Disconnect) Error() string { return d.Message }

// What a connection is being used for.
const (
	UseTerminal = "terminal"
	UseSFTP     = "sftp"
)

// ConnInfo describes one open connection.
type ConnInfo struct {
	ID         uint64
	UserID     int64  // 0 while someone registers with an invite
	Mode       string // the login mode (member, pending, …)
	Started    time.Time
	LastActive time.Time
	Terminals  int // interactive sessions open
	Transfers  int // SFTP sessions open
}

// Conn is one open connection in a Conns registry.
type Conn struct {
	r         *Conns
	id        uint64
	userID    int64
	mode      string
	started   time.Time
	last      atomic.Int64 // unix nanoseconds
	terminals atomic.Int32
	transfers atomic.Int32
	end       func(cause error)
	closeOnce sync.Once
}

// Conns records every authenticated connection, so the server can enforce
// a per-member limit and staff can see who is connected and end a
// connection. Like Tracker it is in memory only.
type Conns struct {
	mu    sync.Mutex
	conns map[uint64]*Conn
	next  uint64
	now   func() time.Time
}

// NewConns returns an empty registry. now may be nil.
func NewConns(now func() time.Time) *Conns {
	if now == nil {
		now = time.Now
	}
	return &Conns{conns: map[uint64]*Conn{}, now: now}
}

// Open records a new connection. When userID is not 0 and max is above 0,
// it fails with ErrTooMany if the member already has max connections open.
// end is called, at most once, to end the connection (see End).
func (r *Conns) Open(userID int64, mode string, max int, end func(cause error)) (*Conn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if userID != 0 && max > 0 {
		n := 0
		for _, c := range r.conns {
			if c.userID == userID {
				n++
			}
		}
		if n >= max {
			return nil, ErrTooMany
		}
	}
	r.next++
	now := r.now()
	c := &Conn{r: r, id: r.next, userID: userID, mode: mode, started: now, end: end}
	c.last.Store(now.UnixNano())
	r.conns[c.id] = c
	return c, nil
}

// ID returns the connection's registry ID.
func (c *Conn) ID() uint64 { return c.id }

// Touch records activity from the member.
func (c *Conn) Touch() { c.last.Store(c.r.now().UnixNano()) }

// LastActive returns when the member last sent anything.
func (c *Conn) LastActive() time.Time { return time.Unix(0, c.last.Load()) }

// Use records that the connection opened a session of the given kind
// (UseTerminal or UseSFTP) and returns the function to call when it ends.
func (c *Conn) Use(kind string) (done func()) {
	n := &c.terminals
	if kind == UseSFTP {
		n = &c.transfers
	}
	n.Add(1)
	var once sync.Once
	return func() { once.Do(func() { n.Add(-1) }) }
}

// Close removes the connection from the registry. Calling it more than once
// has no further effect.
func (c *Conn) Close() {
	c.closeOnce.Do(func() {
		c.r.mu.Lock()
		delete(c.r.conns, c.id)
		c.r.mu.Unlock()
	})
}

func (c *Conn) info() ConnInfo {
	return ConnInfo{
		ID: c.id, UserID: c.userID, Mode: c.mode, Started: c.started, LastActive: c.LastActive(),
		Terminals: int(c.terminals.Load()), Transfers: int(c.transfers.Load()),
	}
}

// List returns the open connections, oldest first.
func (r *Conns) List() []ConnInfo {
	r.mu.Lock()
	out := make([]ConnInfo, 0, len(r.conns))
	for _, c := range r.conns {
		out = append(out, c.info())
	}
	r.mu.Unlock()
	slices.SortFunc(out, func(a, b ConnInfo) int { return cmp.Compare(a.ID, b.ID) })
	return out
}

// Get returns one open connection.
func (r *Conns) Get(id uint64) (ConnInfo, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.conns[id]
	if !ok {
		return ConnInfo{}, false
	}
	return c.info(), true
}

// EndUser ends every open connection of an account, giving cause as the
// reason, and returns how many there were.
func (r *Conns) EndUser(userID int64, cause error) int {
	r.mu.Lock()
	var ends []func(error)
	for _, c := range r.conns {
		if c.userID == userID && userID != 0 {
			ends = append(ends, c.end)
		}
	}
	r.mu.Unlock()
	for _, end := range ends {
		if end != nil {
			end(cause)
		}
	}
	return len(ends)
}

// End asks the server to end a connection, giving cause as the reason. It
// reports false if the connection is no longer open.
func (r *Conns) End(id uint64, cause error) bool {
	r.mu.Lock()
	c, ok := r.conns[id]
	r.mu.Unlock()
	if !ok {
		return false
	}
	if c.end != nil {
		c.end(cause)
	}
	return true
}
