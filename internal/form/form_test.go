package form

import (
	"errors"
	"strings"
	"testing"
)

func TestFieldValidate(t *testing.T) {
	opts := []Option{{Value: "a", Label: "Alpha"}, {Value: "b", Label: "Bravo"}, {Value: "c", Label: "Charlie"}}
	tests := []struct {
		name    string
		f       Field
		in      string
		want    string
		wantErr bool
	}{
		{"text trimmed", Field{Kind: SingleLine}, "  hi  ", "hi", false},
		{"required empty", Field{Kind: SingleLine, Required: true}, "   ", "", true},
		{"optional empty", Field{Kind: SingleLine}, "", "", false},
		{"min length", Field{Kind: SingleLine, MinLen: 3}, "ab", "", true},
		{"max length counts runes", Field{Kind: SingleLine, MaxLen: 3}, "ééé", "ééé", false},
		{"max length exceeded", Field{Kind: SingleLine, MaxLen: 3}, "abcd", "", true},
		{"default single max", Field{Kind: SingleLine}, strings.Repeat("x", DefaultMaxSingle+1), "", true},
		{"control char", Field{Kind: SingleLine}, "a\x1b[31mb", "", true},
		{"bidi override", Field{Kind: SingleLine}, "abc‮dcba", "", true},
		{"invalid utf8", Field{Kind: SingleLine}, "\xff", "", true},
		{"password not trimmed", Field{Kind: SingleLine, Subtype: Password}, " pw ", " pw ", false},
		{"multiline keeps newlines", Field{Kind: MultiLine}, "\r\nline1\r\nline2\n\n", "line1\nline2", false},
		{"multiline tab ok", Field{Kind: MultiLine}, "a\tb", "a\tb", false},
		{"singleline tab refused", Field{Kind: SingleLine}, "a\tb", "", true},
		{"int", Field{Kind: SingleLine, Subtype: Int}, " 042 ", "42", false},
		{"int not number", Field{Kind: SingleLine, Subtype: Int}, "4.2", "", true},
		{"int range", Field{Kind: SingleLine, Subtype: Int, Min: Bound(10), Max: Bound(20)}, "21", "", true},
		{"float", Field{Kind: SingleLine, Subtype: Float}, "3.50", "3.5", false},
		{"float NaN", Field{Kind: SingleLine, Subtype: Float}, "NaN", "", true},
		{"float Inf", Field{Kind: SingleLine, Subtype: Float}, "Inf", "", true},
		{"email", Field{Kind: SingleLine, Subtype: Email}, "a@example.org", "a@example.org", false},
		{"email display name", Field{Kind: SingleLine, Subtype: Email}, "A <a@example.org>", "", true},
		{"phone normalised", Field{Kind: SingleLine, Subtype: Phone}, "+1 (555) 010-0123", "+15550100123", false},
		{"phone no country", Field{Kind: SingleLine, Subtype: Phone}, "555 0100", "", true},
		{"phone letters", Field{Kind: SingleLine, Subtype: Phone}, "+1 555 CALL", "", true},
		{"phone too long", Field{Kind: SingleLine, Subtype: Phone}, "+1234567890123456", "", true},
		{"option", Field{Kind: Choice, Options: opts}, "b", "b", false},
		{"option unknown", Field{Kind: Choice, Options: opts}, "z", "", true},
		{"option two when single", Field{Kind: Choice, Options: opts}, "a,b", "", true},
		{"option multi dedupe", Field{Kind: Choice, Options: opts, Multi: true}, "c, a,c", "c,a", false},
		{"option required", Field{Kind: Choice, Options: opts, Required: true}, " , ", "", true},
		{"bool yes", Field{Kind: Boolean}, "Yes", True, false},
		{"bool empty is false", Field{Kind: Boolean}, "", False, false},
		{"bool junk", Field{Kind: Boolean}, "maybe", "", true},
		{"check hook normalises", Field{Kind: SingleLine, Check: func(s string) (string, error) { return strings.ToLower(s), nil }}, "ABC", "abc", false},
		{"check hook rejects", Field{Kind: SingleLine, Check: func(string) (string, error) { return "", errors.New("no") }}, "x", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.f.Validate(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("Validate(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFormValidate(t *testing.T) {
	fm := Form{
		Fields: []Field{
			{Name: "pw", Kind: SingleLine, Subtype: Password, Required: true},
			{Name: "pw2", Kind: SingleLine, Subtype: Password, Required: true},
			{Name: "age", Kind: SingleLine, Subtype: Int},
		},
		Check: func(v Values) map[string]error {
			if v["pw"] != v["pw2"] {
				return map[string]error{"pw2": errors.New("passwords do not match")}
			}
			return nil
		},
	}
	tests := []struct {
		name     string
		in       Values
		wantErrs []string
	}{
		{"ok", Values{"pw": "x", "pw2": "x", "age": "3"}, nil},
		{"field error skips cross check", Values{"pw": "x", "pw2": "y", "age": "old"}, []string{"age"}},
		{"cross field", Values{"pw": "x", "pw2": "y"}, []string{"pw2"}},
		{"required", Values{}, []string{"pw", "pw2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, errs := fm.Validate(tt.in)
			if len(errs) != len(tt.wantErrs) {
				t.Fatalf("errors = %v, want fields %v", errs, tt.wantErrs)
			}
			for _, n := range tt.wantErrs {
				if errs[n] == nil {
					t.Errorf("missing error for %s", n)
				}
			}
		})
	}
	if fm.Field("age") == nil || fm.Field("nope") != nil {
		t.Error("Field lookup wrong")
	}
}

func TestConstraints(t *testing.T) {
	tests := []struct {
		f    Field
		want string
	}{
		{Field{Kind: SingleLine, MinLen: 3, MaxLen: 32, Required: true}, "3 to 32 characters, required"},
		{Field{Kind: SingleLine, Subtype: Int, Min: Bound(1), Max: Bound(10)}, "whole number, 1 to 10, optional"},
		{Field{Kind: Choice, Multi: true, Required: true}, "choose one or more, required"},
		{Field{Kind: Boolean}, ""},
	}
	for _, tt := range tests {
		if got := tt.f.Constraints(); got != tt.want {
			t.Errorf("Constraints() = %q, want %q", got, tt.want)
		}
	}
}
