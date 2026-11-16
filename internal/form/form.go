// Package form defines the standardised input controls shared by the TUI and
// the web interface (docs/DESIGN.md §7): one field definition, one validator,
// rendered by each front end.
//
// Validation always runs server-side; a front end may validate early for
// convenience but must call Validate before using values.
package form

import (
	"errors"
	"fmt"
	"math"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Kind is the control type.
type Kind int

const (
	SingleLine Kind = iota // one line of text
	MultiLine              // several lines of text
	Choice                 // choose from Options (one, or several if Multi)
	Boolean                // a labelled checkbox
)

// Subtype refines how a SingleLine or MultiLine value is validated and shown.
type Subtype int

const (
	Text      Subtype = iota
	Int               // SingleLine: whole number, optional Min/Max
	Float             // SingleLine: decimal number, optional Min/Max
	Email             // SingleLine: one address, no display name
	Phone             // SingleLine: E.164, normalised to +<digits>
	Password          // SingleLine: never trimmed, never echoed
	Markdown          // MultiLine: markdown source
	PublicKey         // MultiLine: SSH public key; checked by the field's Check hook
)

// Default length limits (in characters) when a field sets none.
const (
	DefaultMaxSingle = 1024
	DefaultMaxMulti  = 64 * 1024
)

// Boolean values as stored in Values.
const (
	True  = "true"
	False = "false"
)

// Option is one choice of a Choice field.
type Option struct {
	Value string // stored value; must not contain ','
	Label string
}

// Field defines one input.
type Field struct {
	Name     string // key in Values
	Label    string
	Help     string // shown on request or under the field
	Kind     Kind
	Subtype  Subtype
	Required bool
	MinLen   int // characters; 0 = no minimum
	MaxLen   int // characters; 0 = kind default
	Min, Max *float64
	Options  []Option
	Multi    bool // Choice: allow several choices (stored comma-separated)
	// Check runs after built-in validation with the normalised value and may
	// normalise further or reject it. Used for rules that live in other
	// packages (e.g. SSH key policy, username rules).
	Check func(string) (string, error)
}

// Values holds normalised field values by name.
type Values map[string]string

// Form is an ordered set of fields.
type Form struct {
	Title  string
	Intro  string
	Fields []Field
	// Check validates across fields after each field is valid; it returns
	// errors keyed by field name (e.g. password confirmation).
	Check func(Values) map[string]error
}

// Errors maps field names to validation errors.
type Errors map[string]error

// Bound is a helper for Field.Min/Max.
func Bound(v float64) *float64 { return &v }

// ErrRequired is returned for an empty required field.
var ErrRequired = errors.New("this field is required")

// maxLen returns the effective maximum length.
func (f *Field) maxLen() int {
	switch {
	case f.MaxLen > 0:
		return f.MaxLen
	case f.Kind == MultiLine:
		return DefaultMaxMulti
	default:
		return DefaultMaxSingle
	}
}

// Constraints describes the field's rules in words, e.g. "3 to 32
// characters". Front ends show it next to the label so rules are never
// conveyed by colour or position alone.
func (f *Field) Constraints() string {
	var parts []string
	switch f.Kind {
	case SingleLine, MultiLine:
		switch f.Subtype {
		case Int:
			parts = append(parts, "whole number")
		case Float:
			parts = append(parts, "number")
		case Email:
			parts = append(parts, "email address")
		case Phone:
			parts = append(parts, "phone number with country code, like +1 555 0100")
		case PublicKey:
			parts = append(parts, "SSH public key, one line")
		}
		if f.Min != nil && f.Max != nil {
			parts = append(parts, fmt.Sprintf("%s to %s", fmtNum(*f.Min), fmtNum(*f.Max)))
		}
		if f.MinLen > 0 && f.MaxLen > 0 {
			parts = append(parts, fmt.Sprintf("%d to %d characters", f.MinLen, f.MaxLen))
		} else if f.MinLen > 0 {
			parts = append(parts, fmt.Sprintf("at least %d characters", f.MinLen))
		}
	case Choice:
		if f.Multi {
			parts = append(parts, "choose one or more")
		} else {
			parts = append(parts, "choose one")
		}
	}
	if f.Required {
		parts = append(parts, "required")
	} else if f.Kind != Boolean {
		parts = append(parts, "optional")
	}
	return strings.Join(parts, ", ")
}

func fmtNum(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }

// Validate checks raw input for this field and returns the normalised value.
func (f *Field) Validate(raw string) (string, error) {
	if !utf8.ValidString(raw) {
		return "", errors.New("contains invalid characters")
	}
	v := raw
	if f.Subtype != Password {
		if f.Kind == MultiLine {
			v = strings.TrimRight(strings.ReplaceAll(v, "\r\n", "\n"), " \t\n")
			v = strings.TrimLeft(v, "\n")
		} else {
			v = strings.TrimSpace(v)
		}
	}
	if err := checkControls(v, f.Kind == MultiLine); err != nil {
		return "", err
	}

	if v == "" {
		if f.Kind == Boolean {
			return False, nil
		}
		if f.Required {
			return "", ErrRequired
		}
		return "", nil
	}

	if f.Kind == SingleLine || f.Kind == MultiLine {
		n := utf8.RuneCountInString(v)
		if f.MinLen > 0 && n < f.MinLen {
			return "", fmt.Errorf("must be at least %d characters", f.MinLen)
		}
		if n > f.maxLen() {
			return "", fmt.Errorf("must be at most %d characters", f.maxLen())
		}
	}

	var err error
	switch f.Kind {
	case SingleLine, MultiLine:
		v, err = f.validateSubtype(v)
	case Choice:
		v, err = f.validateOption(v)
	case Boolean:
		v, err = parseBool(v)
	}
	if err != nil {
		return "", err
	}
	if f.Check != nil {
		return f.Check(v)
	}
	return v, nil
}

// checkControls rejects control characters (and bidirectional overrides,
// which can disguise text). Multi-line values may contain newlines and tabs.
func checkControls(v string, multiline bool) error {
	for _, r := range v {
		if multiline && (r == '\n' || r == '\t') {
			continue
		}
		if unicode.IsControl(r) || isBidiControl(r) {
			return errors.New("contains control characters")
		}
	}
	return nil
}

func isBidiControl(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069) || r == 0x200E || r == 0x200F
}

func (f *Field) validateSubtype(v string) (string, error) {
	switch f.Subtype {
	case Int:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return "", errors.New("must be a whole number")
		}
		if err := f.inRange(float64(n)); err != nil {
			return "", err
		}
		return strconv.FormatInt(n, 10), nil
	case Float:
		n, err := strconv.ParseFloat(v, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return "", errors.New("must be a number")
		}
		if err := f.inRange(n); err != nil {
			return "", err
		}
		return strconv.FormatFloat(n, 'f', -1, 64), nil
	case Email:
		return ValidateEmail(v)
	case Phone:
		return ValidatePhone(v)
	}
	return v, nil
}

func (f *Field) inRange(n float64) error {
	if f.Min != nil && n < *f.Min {
		return fmt.Errorf("must be at least %s", fmtNum(*f.Min))
	}
	if f.Max != nil && n > *f.Max {
		return fmt.Errorf("must be at most %s", fmtNum(*f.Max))
	}
	return nil
}

func (f *Field) validateOption(v string) (string, error) {
	var chosen []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !slices.ContainsFunc(f.Options, func(o Option) bool { return o.Value == p }) {
			return "", errors.New("is not one of the choices")
		}
		if !slices.Contains(chosen, p) {
			chosen = append(chosen, p)
		}
	}
	if len(chosen) == 0 {
		if f.Required {
			return "", ErrRequired
		}
		return "", nil
	}
	if len(chosen) > 1 && !f.Multi {
		return "", errors.New("choose only one")
	}
	return strings.Join(chosen, ","), nil
}

func parseBool(v string) (string, error) {
	switch strings.ToLower(v) {
	case "true", "yes", "y", "1", "on":
		return True, nil
	case "false", "no", "n", "0", "off":
		return False, nil
	}
	return "", errors.New("must be yes or no")
}

// ValidateEmail accepts exactly one address without a display name.
func ValidateEmail(v string) (string, error) {
	const maxEmail = 254
	if len(v) > maxEmail {
		return "", errors.New("email address is too long")
	}
	addr, err := mail.ParseAddress(v)
	if err != nil || addr.Name != "" || addr.Address != v {
		return "", errors.New("is not a valid email address")
	}
	return v, nil
}

// ValidatePhone normalises to E.164 (+ followed by 8 to 15 digits). Spaces,
// dashes, dots and brackets are accepted on input; the country code is
// required.
func ValidatePhone(v string) (string, error) {
	var b strings.Builder
	for i, r := range v {
		switch {
		case r == '+' && i == 0:
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case strings.ContainsRune(" -.()", r):
		default:
			return "", errors.New("is not a valid phone number")
		}
	}
	s := b.String()
	if !strings.HasPrefix(s, "+") {
		return "", errors.New("must start with + and the country code")
	}
	if digits := len(s) - 1; digits < 8 || digits > 15 || s[1] == '0' {
		return "", errors.New("is not a valid international phone number")
	}
	return s, nil
}

// Validate checks every field and then the form-level Check. It returns the
// normalised values and any errors; values for invalid fields are omitted.
func (fm *Form) Validate(in Values) (Values, Errors) {
	out := Values{}
	errs := Errors{}
	for i := range fm.Fields {
		f := &fm.Fields[i]
		v, err := f.Validate(in[f.Name])
		if err != nil {
			errs[f.Name] = err
			continue
		}
		out[f.Name] = v
	}
	if len(errs) == 0 && fm.Check != nil {
		for name, err := range fm.Check(out) {
			if err != nil {
				errs[name] = err
			}
		}
	}
	if len(errs) == 0 {
		return out, nil
	}
	return out, errs
}

// Field returns the named field, or nil.
func (fm *Form) Field(name string) *Field {
	for i := range fm.Fields {
		if fm.Fields[i].Name == name {
			return &fm.Fields[i]
		}
	}
	return nil
}
