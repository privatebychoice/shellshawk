package linkgrade

import (
	"os"
	"path/filepath"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/theme"
)

func TestGrade(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data.json")
	// A local dataset entry (example.org is reserved for documentation).
	if err := os.WriteFile(data, []byte(`{"example.org": {"trust": "audited", "verified": "2026-07-01",
		"signals": {"adTrackingCookies": "no", "honorsGPC": "yes", "adsTrackers": "none",
		"thirdPartyScripts": "none", "fingerprinting": "no", "sessionReplay": "no", "sellsSharesData": "no"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := New(data, []string{"bbs.example.net"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tests := []struct {
		url        string
		wantLetter string
	}{
		{"https://example.org/page", "A"},
		{"https://www.youtube.com/watch?v=x", "F"}, // built-in dataset
		{"https://unknown-site.example/", "?"},
		{"not a url", "?"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			r := g.Grade(tt.url)
			if r.Letter != tt.wantLetter {
				t.Errorf("Grade(%q) = %+v, want letter %s", tt.url, r, tt.wantLetter)
			}
			if r.Token != TokenFor(r.Letter) || r.Name == "" {
				t.Errorf("incomplete result %+v", r)
			}
		})
	}

	if _, err := New(filepath.Join(t.TempDir(), "missing.json"), nil); err == nil {
		t.Error("missing data file accepted")
	}
}

func TestTokenFor(t *testing.T) {
	want := map[string]theme.Token{"A": theme.GradeA, "b": theme.GradeB, "C": theme.GradeC, "D": theme.GradeD, "F": theme.GradeF, "?": theme.GradeUnknown, "E": theme.GradeUnknown}
	for l, tok := range want {
		if got := TokenFor(l); got != tok {
			t.Errorf("TokenFor(%q) = %s, want %s", l, got, tok)
		}
	}
}
