package term

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDecoder(t *testing.T) {
	r := func(c rune) Event { return Event{Key: KeyRune, Rune: c} }
	k := func(key Key) Event { return Event{Key: key} }
	tests := []struct {
		name   string
		chunks []string
		flush  bool
		want   []Event
	}{
		{"ascii", []string{"ab"}, false, []Event{r('a'), r('b')}},
		{"utf8 split across chunks", []string{"\xc3", "\xa9"}, false, []Event{r('é')}},
		{"enter CR", []string{"\r"}, false, []Event{k(KeyEnter)}},
		{"CRLF is one enter", []string{"\r\n"}, false, []Event{k(KeyEnter)}},
		{"LF alone", []string{"\n\n"}, false, []Event{k(KeyEnter), k(KeyEnter)}},
		{"backspace variants", []string{"\x7f\x08"}, false, []Event{k(KeyBackspace), k(KeyBackspace)}},
		{"tab and backtab", []string{"\t\x1b[Z"}, false, []Event{k(KeyTab), k(KeyBacktab)}},
		{"ctrl keys", []string{"\x03\x15"}, false, []Event{{Key: KeyCtrl, Rune: 'c'}, {Key: KeyCtrl, Rune: 'u'}}},
		{"arrows CSI", []string{"\x1b[A\x1b[B\x1b[C\x1b[D"}, false, []Event{k(KeyUp), k(KeyDown), k(KeyRight), k(KeyLeft)}},
		{"arrows SS3", []string{"\x1bOA\x1bOD"}, false, []Event{k(KeyUp), k(KeyLeft)}},
		{"modified arrow", []string{"\x1b[1;5C"}, false, []Event{k(KeyRight)}},
		{"home end variants", []string{"\x1b[H\x1b[F\x1b[1~\x1b[4~\x1bOH"}, false, []Event{k(KeyHome), k(KeyEnd), k(KeyHome), k(KeyEnd), k(KeyHome)}},
		{"delete pgup pgdn", []string{"\x1b[3~\x1b[5~\x1b[6~"}, false, []Event{k(KeyDelete), k(KeyPgUp), k(KeyPgDn)}},
		{"sequence split across chunks", []string{"\x1b[", "A"}, false, []Event{k(KeyUp)}},
		{"lone esc waits", []string{"\x1b"}, false, nil},
		{"lone esc after timeout", []string{"\x1b"}, true, []Event{k(KeyEsc)}},
		{"esc esc", []string{"\x1b\x1b[A"}, false, []Event{k(KeyEsc), k(KeyUp)}},
		{"alt+x is esc then x", []string{"\x1bx"}, false, []Event{k(KeyEsc), r('x')}},
		{"unknown CSI ignored", []string{"\x1b[99q", "z"}, false, []Event{r('z')}},
		{"C1 controls dropped", []string{"a\u009bb"}, false, []Event{r('a'), r('b')}},
		{"invalid utf8 dropped", []string{"a\xffb"}, false, []Event{r('a'), r('b')}},
		{"bracketed paste", []string{"\x1b[200~line1\nline2\x1b[201~x"}, false, []Event{{Key: KeyPaste, Text: "line1\nline2"}, r('x')}},
		{"paste split, end marker split", []string{"\x1b[200~ab", "c\x1b[20", "1~"}, false, []Event{{Key: KeyPaste, Text: "abc"}}},
		{"paste with escapes inside is literal", []string{"\x1b[200~\x1b[A\x1b[201~"}, false, []Event{{Key: KeyPaste, Text: "\x1b[A"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Decoder
			var got []Event
			for _, c := range tt.chunks {
				got = append(got, d.Feed([]byte(c))...)
			}
			if tt.flush {
				got = append(got, d.Flush()...)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("events = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestDecoderLimits(t *testing.T) {
	var d Decoder
	// An overlong CSI must not buffer forever.
	evs := d.Feed([]byte("\x1b[" + strings.Repeat("1", 100) + "A"))
	if d.Pending() {
		t.Error("overlong CSI left bytes pending")
	}
	_ = evs
	// Paste is capped.
	d = Decoder{}
	evs = d.Feed([]byte("\x1b[200~" + strings.Repeat("x", maxPasteLen+100) + "\x1b[201~"))
	if len(evs) != 1 || len(evs[0].Text) != maxPasteLen {
		t.Errorf("paste length = %d, want cap %d", len(evs[0].Text), maxPasteLen)
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct {
		in, want string
		keepNL   bool
	}{
		{"plain", "plain", false},
		{"red\x1b[31mtext\x1b]0;title\x07", "red[31mtext]0;title", false},
		{"a\tb", "a b", false},
		{"line1\nline2", "line1line2", false},
		{"line1\nline2", "line1\nline2", true},
		{"rtl‮evil", "rtlevil", false},
		{"c1\u009b31m", "c131m", false},
	}
	for _, tt := range tests {
		if got := Sanitize(tt.in, tt.keepNL); got != tt.want {
			t.Errorf("Sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestWidthAndWrap(t *testing.T) {
	widths := map[string]int{"abc": 3, "日本": 4, "é": 1, "😀": 2, "": 0}
	for s, want := range widths {
		if got := Width(s); got != want {
			t.Errorf("Width(%q) = %d, want %d", s, got, want)
		}
	}
	if got := Truncate("日本語", 5); got != "日本" {
		t.Errorf("Truncate = %q", got)
	}
	if got := Pad("ab", 4); got != "ab  " {
		t.Errorf("Pad = %q", got)
	}
	tests := []struct {
		in   string
		w    int
		want []string
	}{
		{"the quick brown fox", 10, []string{"the quick", "brown fox"}},
		{"a\nb", 10, []string{"a", "b"}},
		{"abcdefghij", 4, []string{"abcd", "efgh", "ij"}},
		{"", 5, []string{""}},
	}
	for _, tt := range tests {
		if got := Wrap(tt.in, tt.w); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Wrap(%q, %d) = %q, want %q", tt.in, tt.w, got, tt.want)
		}
	}
}

func TestTerminalEscTimeout(t *testing.T) {
	pr, pw := io.Pipe()
	tm := New(pr, io.Discard, true, Size{80, 24}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go pw.Write([]byte("\x1b"))
	ev, err := tm.Next(ctx)
	if err != nil || ev.Key != KeyEsc {
		t.Fatalf("lone ESC: %+v, %v", ev, err)
	}
	pw.Close()
	if _, err := tm.Next(ctx); err != io.EOF {
		t.Errorf("after close err = %v, want EOF", err)
	}
}

func TestTerminalResize(t *testing.T) {
	pr, _ := io.Pipe()
	rs := make(chan Size, 1)
	tm := New(pr, io.Discard, true, Size{80, 24}, rs)
	rs <- Size{100, 40}
	ev, err := tm.Next(context.Background())
	if err != nil || ev.Key != KeyResize || tm.Size() != (Size{100, 40}) {
		t.Errorf("resize: %+v %v %+v", ev, err, tm.Size())
	}
}
