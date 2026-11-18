package term

import (
	"bytes"
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// escTimeout is how long a lone ESC waits for the rest of a sequence before
// being reported as the Esc key.
const escTimeout = 50 * time.Millisecond

// Size is a terminal size in cells.
type Size struct{ Cols, Rows int }

// Terminal reads key events from, and buffers output to, an SSH session.
type Terminal struct {
	w      io.Writer
	out    bytes.Buffer
	events chan Event
	errc   chan error
	resize <-chan Size

	mu   sync.Mutex
	size Size

	writeMu sync.Mutex  // serialises writes from Flush and Notify
	screen  atomic.Bool // a full-screen UI is drawing
	redraw  atomic.Bool // a notice was drawn over the screen

	// PTY reports whether the client allocated a terminal. Without one the
	// client's own terminal echoes and edits lines, input arrives a line at
	// a time, and full-screen drawing is impossible.
	PTY bool
}

// New starts reading from r. size is the initial size (zero if no PTY);
// resize delivers changes and may be nil. The reader goroutine stops when r
// returns an error (the session ends).
func New(r io.Reader, w io.Writer, pty bool, size Size, resize <-chan Size) *Terminal {
	t := &Terminal{w: w, events: make(chan Event, 64), errc: make(chan error, 1), resize: resize, size: size, PTY: pty}
	go t.readLoop(r)
	return t
}

func (t *Terminal) readLoop(r io.Reader) {
	chunks := make(chan []byte)
	errc := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunks <- bytes.Clone(buf[:n])
			}
			if err != nil {
				errc <- err
				close(chunks)
				return
			}
		}
	}()

	var dec Decoder
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	emit := func(evs []Event) {
		// After a notice was drawn over the full screen, the first input
		// is preceded by a resize event so the UI draws itself again.
		if len(evs) > 0 && t.redraw.Swap(false) {
			t.events <- Event{Key: KeyResize}
		}
		for _, ev := range evs {
			t.events <- ev
		}
	}
	for {
		select {
		case c, ok := <-chunks:
			if !ok {
				emit(dec.Flush())
				t.errc <- <-errc
				return
			}
			emit(dec.Feed(c))
			if dec.Pending() {
				timer.Reset(escTimeout)
			}
		case <-timer.C:
			emit(dec.Flush())
		}
	}
}

// Next returns the next event, a KeyResize event when the size changes, or
// an error when the input ends or ctx is cancelled.
func (t *Terminal) Next(ctx context.Context) (Event, error) {
	select {
	case ev := <-t.events:
		return ev, nil
	default:
	}
	select {
	case ev := <-t.events:
		return ev, nil
	case s := <-t.resize:
		t.mu.Lock()
		t.size = s
		t.mu.Unlock()
		return Event{Key: KeyResize}, nil
	case err := <-t.errc:
		t.errc <- err // keep reporting it
		// select chooses randomly among ready cases; input that arrived
		// before the stream ended must still be delivered first.
		select {
		case ev := <-t.events:
			return ev, nil
		default:
		}
		return Event{}, err
	case <-ctx.Done():
		return Event{}, ctx.Err()
	}
}

// NextWake is Next that also returns (with woke true) when wake receives,
// so a caller can react to outside events such as new chat messages.
func (t *Terminal) NextWake(ctx context.Context, wake <-chan struct{}) (ev Event, woke bool, err error) {
	select {
	case ev := <-t.events:
		return ev, false, nil
	default:
	}
	select {
	case ev := <-t.events:
		return ev, false, nil
	case <-wake:
		return Event{}, true, nil
	case s := <-t.resize:
		t.mu.Lock()
		t.size = s
		t.mu.Unlock()
		return Event{Key: KeyResize}, false, nil
	case err := <-t.errc:
		t.errc <- err
		select {
		case ev := <-t.events:
			return ev, false, nil
		default:
		}
		return Event{}, false, err
	case <-ctx.Done():
		return Event{}, false, ctx.Err()
	}
}

// Size returns the current terminal size.
func (t *Terminal) Size() Size {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.size
}

// WriteString buffers raw output (escape sequences included). Callers must
// Sanitize any user-supplied text first.
func (t *Terminal) WriteString(s string) { t.out.WriteString(s) }

// SetScreen tells the terminal whether a full-screen UI is drawing, which
// decides how Notify shows a notice.
func (t *Terminal) SetScreen(on bool) { t.screen.Store(on) }

// Notify shows msg at once, from any goroutine, without disturbing what the
// UI is doing: in full screen as a highlighted line at the bottom (the
// screen is drawn again on the next key), otherwise as a line of its own so
// a screen reader announces it. It rings the bell to draw attention. msg
// must not contain user-supplied text.
func (t *Terminal) Notify(msg string) error {
	var b bytes.Buffer
	if t.screen.Load() {
		size := t.Size()
		b.WriteString("\x1b7" + MoveTo(max(size.Rows-1, 0), 0) + ClearLine + "\x1b[7m")
		b.WriteString(Truncate(msg, max(size.Cols-1, 1)))
		b.WriteString("\x1b[0m\x1b8\a")
		t.redraw.Store(true)
	} else {
		b.WriteString("\a\r\n" + msg + "\r\n")
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err := t.w.Write(b.Bytes())
	return err
}

// Flush sends buffered output.
func (t *Terminal) Flush() error {
	if t.out.Len() == 0 {
		return nil
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_, err := t.w.Write(t.out.Bytes())
	t.out.Reset()
	return err
}
