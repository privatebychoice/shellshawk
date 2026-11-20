package tui

import (
	"errors"
	"fmt"
	"testing"
)

func TestSentence(t *testing.T) {
	errInvalid := errors.New("invalid poll")
	errOther := errors.New("invalid")
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"prefix dropped", fmt.Errorf("%w: the question is empty", errInvalid), "The question is empty."},
		{"nested prefixes", fmt.Errorf("%w: %w: too long", errOther, errInvalid), "Too long."},
		{"no prefix", errors.New("this poll is closed"), "This poll is closed."},
		{"keeps a full stop", errors.New("done."), "Done."},
		{"keeps a question mark", errors.New("really?"), "Really?"},
		{"only the prefix", errors.New("invalid poll: "), ""},
		{"non-ASCII first letter", errors.New("ébauche"), "Ébauche."},
		{"nil", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Sentence(tt.err, errInvalid, errOther); got != tt.want {
				t.Errorf("Sentence = %q, want %q", got, tt.want)
			}
		})
	}
}
