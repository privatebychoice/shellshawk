package tui

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Sentence words an expected error for a member. It drops the prefixes of
// the given sentinel errors ("invalid poll: the question is empty" becomes
// "the question is empty"), starts with a capital letter and ends with a
// full stop. Errors that begin with a username are worded so the name is
// not first, since a capital would change it.
func Sentence(err error, prefixes ...error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for cut := true; cut; {
		cut = false
		for _, p := range prefixes {
			if rest, ok := strings.CutPrefix(msg, p.Error()+": "); ok {
				msg, cut = rest, true
			}
		}
	}
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return ""
	}
	r, n := utf8.DecodeRuneInString(msg)
	msg = string(unicode.ToUpper(r)) + msg[n:]
	if !strings.HasSuffix(msg, ".") && !strings.HasSuffix(msg, "?") && !strings.HasSuffix(msg, "!") {
		msg += "."
	}
	return msg
}
