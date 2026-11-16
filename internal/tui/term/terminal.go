package term

import (
	"bytes"
	"context"
	"io"
	"sync"
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

// Size returns the current terminal size.
func (t *Terminal) Size() Size {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.size
}

// WriteString buffers raw output (escape sequences included). Callers must
// Sanitize any user-supplied text first.
func (t *Terminal) WriteString(s string) { t.out.WriteString(s) }

// Flush sends buffered output.
func (t *Terminal) Flush() error {
	if t.out.Len() == 0 {
		return nil
	}
	_, err := t.w.Write(t.out.Bytes())
	t.out.Reset()
	return err
}
