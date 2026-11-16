package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestValidateUsername(t *testing.T) {
	tests := []struct {
		in   string
		want error
	}{
		{"alice", nil},
		{"bob_99", nil},
		{"a-b", nil},
		{"ab", ErrUsernameInvalid},
		{strings.Repeat("a", 33), ErrUsernameInvalid},
		{"9lives", ErrUsernameInvalid},
		{"has space", ErrUsernameInvalid},
		{"UPPER", ErrUsernameInvalid}, // callers normalize first
		{"ünïcode", ErrUsernameInvalid},
		{"admin", ErrUsernameReserved},
		{"root", ErrUsernameReserved},
		{"new", ErrUsernameReserved},
		{"signup", ErrUsernameReserved}, // configured invite user below
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := ValidateUsername(tt.in, "SignUp"); !errors.Is(got, tt.want) {
				t.Errorf("ValidateUsername(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name string
		pw   string
		ok   bool
	}{
		{"min length", strings.Repeat("a", MinPasswordLen), true},
		{"too short", strings.Repeat("a", MinPasswordLen-1), false},
		{"max length", strings.Repeat("a", MaxPasswordLen), true},
		{"too long", strings.Repeat("a", MaxPasswordLen+1), false},
		{"counts runes not bytes", strings.Repeat("é", MinPasswordLen), true},
		{"invalid utf-8", strings.Repeat("\xff", MinPasswordLen), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePassword(tt.pw); (err == nil) != tt.ok {
				t.Errorf("ValidatePassword = %v, ok %v", err, tt.ok)
			}
		})
	}
}

func TestPasswordHash(t *testing.T) {
	ctx := context.Background()
	h, err := HashPassword(ctx, testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Errorf("hash format = %q", h)
	}
	h2, _ := HashPassword(ctx, testPassword)
	if h == h2 {
		t.Error("two hashes of the same password are identical; salt missing")
	}

	parts := strings.Split(h, "$")
	tests := []struct {
		name    string
		pw      string
		hash    string
		want    bool
		wantErr bool
	}{
		{"correct", testPassword, h, true, false},
		{"wrong", testPassword + "!", h, false, false},
		{"not argon2id", testPassword, strings.Replace(h, "argon2id", "argon2i", 1), false, true},
		{"too few parts", testPassword, "$argon2id$v=19", false, true},
		{"huge memory refused", testPassword, strings.Replace(h, "m=19456", "m=99999999", 1), false, true},
		{"bad salt", testPassword, strings.Join([]string{"", parts[1], parts[2], parts[3], "!!", parts[5]}, "$"), false, true},
		{"empty", testPassword, "", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyPassword(ctx, []byte(tt.pw), tt.hash)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("VerifyPassword = %v, %v; want %v, err %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestInviteCodeFormat(t *testing.T) {
	code, err := newInviteCode()
	if err != nil {
		t.Fatal(err)
	}
	norm := NormalizeInviteCode(code)
	if len(norm) != 26 { // 128 bits in base32
		t.Errorf("normalized length = %d, want 26 (%s)", len(norm), code)
	}
	if strings.ContainsAny(norm, "ILOU") {
		t.Errorf("code contains ambiguous characters: %s", code)
	}

	tests := []struct{ in, want string }{
		{"abcd-efgh", "ABCDEFGH"},
		{" ab cd\t", "ABCD"},
		{"o0-il1", "00111"},
	}
	for _, tt := range tests {
		if got := NormalizeInviteCode(tt.in); got != tt.want {
			t.Errorf("NormalizeInviteCode(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
	if hashInviteCode("abcd-efgh") != hashInviteCode("ABCDEFGH") {
		t.Error("hash differs for equivalent codes")
	}
}

func TestNormalizeEmail(t *testing.T) {
	tests := []struct {
		in, want string
		ok       bool
	}{
		{"", "", true},
		{"  a@example.org ", "a@example.org", true},
		{"Name <a@example.org>", "", false},
		{"not-an-email", "", false},
		{strings.Repeat("a", 250) + "@x.org", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := NormalizeEmail(tt.in)
			if (err == nil) != tt.ok || got != tt.want {
				t.Errorf("NormalizeEmail(%q) = %q, %v", tt.in, got, err)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	good, _ := newKeyLine(t, "laptop")
	other, _ := newKeyLine(t, "")
	tests := []struct {
		name        string
		line        string
		ok          bool
		wantComment string
	}{
		{"ed25519 with comment", good, true, "laptop"},
		{"surrounding whitespace", "  " + good + "\n", true, "laptop"},
		{"options refused", `command="sh" ` + good, false, ""},
		{"two keys refused", good + "\n" + other, false, ""},
		{"rsa 2048 refused by policy", rsaKeyLine(t, 2048), false, ""},
		{"garbage", "ssh-ed25519 AAAAnotbase64", false, ""},
		{"empty", "", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, comment, err := ParsePublicKey(tt.line)
			if (err == nil) != tt.ok {
				t.Fatalf("ParsePublicKey err = %v, ok %v", err, tt.ok)
			}
			if tt.ok && comment != tt.wantComment {
				t.Errorf("comment = %q, want %q", comment, tt.wantComment)
			}
			if !tt.ok && !errors.Is(err, ErrKeyInvalid) {
				t.Errorf("err = %v, want ErrKeyInvalid", err)
			}
		})
	}
}
