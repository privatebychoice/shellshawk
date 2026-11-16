// Package term decodes terminal input into key events and provides output
// helpers: text width, sanitising, and screen control sequences.
package term

import (
	"bytes"
	"strconv"
	"unicode/utf8"
)

// Key identifies a key press.
type Key int

const (
	KeyNone Key = iota
	KeyRune     // printable character in Event.Rune
	KeyEnter
	KeyBackspace
	KeyDelete
	KeyTab
	KeyBacktab
	KeyUp
	KeyDown
	KeyLeft
	KeyRight
	KeyHome
	KeyEnd
	KeyPgUp
	KeyPgDn
	KeyEsc
	KeyCtrl   // Ctrl+letter in Event.Rune ('a'..'z')
	KeyPaste  // bracketed paste; text in Event.Text
	KeyResize // terminal size changed
)

// Event is one decoded input event.
type Event struct {
	Key  Key
	Rune rune
	Text string
}

// Limits protecting the decoder from hostile input.
const (
	maxSeqLen   = 32        // longest escape sequence accepted
	maxPasteLen = 64 * 1024 // bracketed paste is truncated beyond this
)

var (
	pasteStart = []byte("\x1b[200~")
	pasteEnd   = []byte("\x1b[201~")
)

// Decoder turns a byte stream into events. It keeps state across Feed
// calls for split UTF-8, escape sequences and bracketed paste.
type Decoder struct {
	buf     []byte
	inPaste bool
	paste   []byte
	lastCR  bool // swallow the \n of \r\n
}

// Feed decodes as much of data (plus buffered input) as possible. Bytes that
// may be the start of an incomplete sequence stay buffered; Pending reports
// whether any are waiting, and Flush forces them out after a timeout.
func (d *Decoder) Feed(data []byte) []Event {
	d.buf = append(d.buf, data...)
	return d.decode(false)
}

// Pending reports whether bytes are buffered awaiting more input.
func (d *Decoder) Pending() bool { return len(d.buf) > 0 }

// Flush decodes buffered bytes without waiting for more: a lone ESC becomes
// KeyEsc. Call it when no input has arrived for a short while.
func (d *Decoder) Flush() []Event { return d.decode(true) }

func (d *Decoder) decode(force bool) []Event {
	var out []Event
	for len(d.buf) > 0 {
		if d.inPaste {
			i := bytes.Index(d.buf, pasteEnd)
			if i < 0 {
				// Keep a tail that could be the start of the end marker.
				keep := min(len(d.buf), len(pasteEnd)-1)
				d.addPaste(d.buf[:len(d.buf)-keep])
				d.buf = d.buf[len(d.buf)-keep:]
				if force {
					d.addPaste(d.buf)
					d.buf = nil
				}
				break
			}
			d.addPaste(d.buf[:i])
			d.buf = d.buf[i+len(pasteEnd):]
			d.inPaste = false
			out = append(out, Event{Key: KeyPaste, Text: string(bytes.ToValidUTF8(d.paste, nil))})
			d.paste = nil
			continue
		}

		b := d.buf[0]
		if b == 0x1b {
			ev, n, complete := parseEscape(d.buf)
			if !complete {
				if !force {
					break // wait for the rest
				}
				// Timed out: a lone ESC, or ESC followed by ordinary input.
				out = append(out, Event{Key: KeyEsc})
				d.buf = d.buf[1:]
				continue
			}
			d.buf = d.buf[n:]
			if ev.Key == KeyPaste {
				d.inPaste = true
				continue
			}
			if ev.Key != KeyNone {
				out = append(out, ev)
			}
			d.lastCR = false
			continue
		}

		if b < 0x20 || b == 0x7f {
			d.buf = d.buf[1:]
			if b == '\n' && d.lastCR {
				d.lastCR = false
				continue
			}
			d.lastCR = b == '\r'
			if ev, ok := controlKey(b); ok {
				out = append(out, ev)
			}
			continue
		}
		d.lastCR = false

		if !utf8.FullRune(d.buf) && !force {
			break
		}
		r, n := utf8.DecodeRune(d.buf)
		d.buf = d.buf[n:]
		if r == utf8.RuneError && n <= 1 {
			continue // drop invalid bytes
		}
		if r >= 0x80 && r <= 0x9f {
			continue // C1 controls
		}
		out = append(out, Event{Key: KeyRune, Rune: r})
	}
	return out
}

func (d *Decoder) addPaste(b []byte) {
	if room := maxPasteLen - len(d.paste); room > 0 {
		d.paste = append(d.paste, b[:min(len(b), room)]...)
	}
}

func controlKey(b byte) (Event, bool) {
	switch b {
	case '\r', '\n':
		return Event{Key: KeyEnter}, true
	case 0x7f, 0x08:
		return Event{Key: KeyBackspace}, true
	case '\t':
		return Event{Key: KeyTab}, true
	case 0x00:
		return Event{}, false
	}
	if b >= 0x01 && b <= 0x1a {
		return Event{Key: KeyCtrl, Rune: rune('a' + b - 1)}, true
	}
	return Event{}, false // other C0 controls are ignored
}

// parseEscape parses an escape sequence at the start of b (b[0] == ESC).
// complete is false if b may be a prefix of a longer sequence.
func parseEscape(b []byte) (ev Event, n int, complete bool) {
	if len(b) < 2 {
		return Event{}, 0, false
	}
	switch b[1] {
	case '[':
		return parseCSI(b)
	case 'O':
		if len(b) < 3 {
			return Event{}, 0, false
		}
		switch b[2] {
		case 'A':
			return Event{Key: KeyUp}, 3, true
		case 'B':
			return Event{Key: KeyDown}, 3, true
		case 'C':
			return Event{Key: KeyRight}, 3, true
		case 'D':
			return Event{Key: KeyLeft}, 3, true
		case 'H':
			return Event{Key: KeyHome}, 3, true
		case 'F':
			return Event{Key: KeyEnd}, 3, true
		}
		return Event{}, 3, true // F1–F4 etc.: ignored
	case 0x1b:
		// ESC ESC: the first is a lone Esc.
		return Event{Key: KeyEsc}, 1, true
	}
	// ESC + other byte (Alt+key): report Esc and let the byte be decoded.
	return Event{Key: KeyEsc}, 1, true
}

func parseCSI(b []byte) (Event, int, bool) {
	i := 2
	for ; i < len(b); i++ {
		c := b[i]
		if c >= 0x40 && c <= 0x7e {
			break
		}
		if c < 0x20 || i >= maxSeqLen {
			// Malformed or overlong: discard what we have.
			return Event{}, i, true
		}
	}
	if i >= len(b) {
		return Event{}, 0, false
	}
	params, final, n := string(b[2:i]), b[i], i+1

	switch final {
	case 'A':
		return Event{Key: KeyUp}, n, true
	case 'B':
		return Event{Key: KeyDown}, n, true
	case 'C':
		return Event{Key: KeyRight}, n, true
	case 'D':
		return Event{Key: KeyLeft}, n, true
	case 'H':
		return Event{Key: KeyHome}, n, true
	case 'F':
		return Event{Key: KeyEnd}, n, true
	case 'Z':
		return Event{Key: KeyBacktab}, n, true
	case '~':
		num := params
		if j := bytes.IndexByte([]byte(params), ';'); j >= 0 {
			num = params[:j]
		}
		v, _ := strconv.Atoi(num)
		switch v {
		case 1, 7:
			return Event{Key: KeyHome}, n, true
		case 4, 8:
			return Event{Key: KeyEnd}, n, true
		case 3:
			return Event{Key: KeyDelete}, n, true
		case 5:
			return Event{Key: KeyPgUp}, n, true
		case 6:
			return Event{Key: KeyPgDn}, n, true
		case 200:
			return Event{Key: KeyPaste}, n, true
		}
	}
	return Event{}, n, true // unknown sequence: ignored
}
