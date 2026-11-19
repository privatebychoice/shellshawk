package chat

import (
	"slices"
	"strings"
	"sync"
	"time"

	"go.privatebychoice.com/shellshawk/internal/tui"
)

// Flood control: at most floodLines messages per floodWindow per member.
const (
	floodLines  = 5
	floodWindow = 5 * time.Second
	outboxSize  = 64 // lines buffered per member before they are dropped
)

// hub tracks who is in each channel and delivers lines to them. It is in
// memory only.
type hub struct {
	mu    sync.Mutex
	rooms map[int64]map[*member]struct{}
	sent  map[int64][]time.Time // flood control per user
}

// member is one session inside one channel.
type member struct {
	userID int64
	name   string
	out    chan tui.Line
	once   sync.Once
}

// close ends the member's view, first delivering final if it is not nil.
func (m *member) close(final tui.Line) {
	m.once.Do(func() {
		if final != nil {
			select {
			case m.out <- final:
			default:
			}
		}
		close(m.out)
	})
}

func newHub() *hub {
	return &hub{rooms: map[int64]map[*member]struct{}{}, sent: map[int64][]time.Time{}}
}

func (h *hub) join(channel, userID int64, name string) *member {
	m := &member{userID: userID, name: name, out: make(chan tui.Line, outboxSize)}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.rooms[channel] == nil {
		h.rooms[channel] = map[*member]struct{}{}
	}
	h.rooms[channel][m] = struct{}{}
	return m
}

func (h *hub) leave(channel int64, m *member) {
	h.mu.Lock()
	delete(h.rooms[channel], m)
	if len(h.rooms[channel]) == 0 {
		delete(h.rooms, channel)
	}
	h.mu.Unlock()
	m.close(nil)
}

// broadcast delivers l to everyone in channel. A member whose buffer is
// full misses the line rather than stalling everyone else.
func (h *hub) broadcast(channel int64, l tui.Line) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for m := range h.rooms[channel] {
		select {
		case m.out <- l:
		default:
		}
	}
}

// tell delivers l to every chat user is in, and reports whether any
// session received it.
func (h *hub) tell(user int64, l tui.Line) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	told := false
	for _, room := range h.rooms {
		for m := range room {
			if m.userID != user {
				continue
			}
			select {
			case m.out <- l:
				told = true
			default:
			}
		}
	}
	return told
}

// who returns the distinct usernames in channel, sorted.
func (h *hub) who(channel int64) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []string
	for m := range h.rooms[channel] {
		if !slices.Contains(out, m.name) {
			out = append(out, m.name)
		}
	}
	slices.SortFunc(out, strings.Compare)
	return out
}

// count returns how many distinct members are in channel.
func (h *hub) count(channel int64) int { return len(h.who(channel)) }

// kick removes every session of user from channel, telling them why.
func (h *hub) kick(channel, user int64, why string) {
	h.mu.Lock()
	var gone []*member
	for m := range h.rooms[channel] {
		if m.userID == user {
			gone = append(gone, m)
			delete(h.rooms[channel], m)
		}
	}
	h.mu.Unlock()
	for _, m := range gone {
		m.close(tui.Text(why))
	}
}

// closeRoom removes everyone from channel.
func (h *hub) closeRoom(channel int64, why string) {
	h.mu.Lock()
	room := h.rooms[channel]
	delete(h.rooms, channel)
	h.mu.Unlock()
	for m := range room {
		m.close(tui.Text(why))
	}
}

// allow reports whether user may send another line now (flood control).
func (h *hub) allow(user int64, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	recent := slices.DeleteFunc(h.sent[user], func(t time.Time) bool { return now.Sub(t) >= floodWindow })
	if len(recent) >= floodLines {
		h.sent[user] = recent
		return false
	}
	h.sent[user] = append(recent, now)
	return true
}
