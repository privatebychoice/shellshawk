package web

import (
	"net/http"
	"strconv"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/form"
)

// A small renderer for form.Form, so settings declared by plugins get an
// accessible web form without each plugin writing HTML: every input has a
// label, its rules in words, its help, and its error tied to it with
// aria-describedby. Input names carry a prefix so a field can never clash
// with the form's own fields (csrf).

const fieldPrefix = "f-"

type optionView struct {
	Value, Label string
	Selected     bool
}

type fieldView struct {
	ID, Name, Label, Help, Rules, Error, Value string
	Control                                    string // text, number, email, tel, password, textarea, select, checkboxes, checkbox
	Step, Min, Max                             string
	MaxLen                                     int
	Required, Empty                            bool // Empty: a select offers "no choice"
	Options                                    []optionView
}

// Describe is the aria-describedby value: rules, help and error ids.
func (f fieldView) Describe() string {
	ids := []string{f.ID + "-rules"}
	if f.Help != "" {
		ids = append(ids, f.ID+"-help")
	}
	if f.Error != "" {
		ids = append(ids, f.ID+"-error")
	}
	return strings.Join(ids, " ")
}

// fieldViews prepares fm's fields for the "fields" template with values and
// field errors.
func fieldViews(fm *form.Form, vals form.Values, errs form.Errors) []fieldView {
	out := make([]fieldView, 0, len(fm.Fields))
	for _, f := range fm.Fields {
		v := fieldView{
			ID: fieldPrefix + f.Name, Name: fieldPrefix + f.Name, Label: f.Label, Help: f.Help, Rules: f.Constraints(),
			Value: vals[f.Name], Required: f.Required,
		}
		if err := errs[f.Name]; err != nil {
			v.Error = f.Label + " " + err.Error() + "."
		}
		if f.Min != nil {
			v.Min = fmtBound(*f.Min)
		}
		if f.Max != nil {
			v.Max = fmtBound(*f.Max)
		}
		switch f.Kind {
		case form.MultiLine:
			v.Control, v.MaxLen = "textarea", maxLen(f)
		case form.Boolean:
			v.Control = "checkbox"
		case form.Choice:
			chosen := map[string]bool{}
			for _, c := range strings.Split(v.Value, ",") {
				chosen[c] = true
			}
			for _, o := range f.Options {
				v.Options = append(v.Options, optionView{Value: o.Value, Label: o.Label, Selected: chosen[o.Value]})
			}
			v.Control = "select"
			if f.Multi {
				v.Control = "checkboxes"
			}
			v.Empty = !f.Required && !f.Multi
		default:
			v.MaxLen = maxLen(f)
			switch f.Subtype {
			case form.Int:
				v.Control, v.Step = "number", "1"
			case form.Float:
				v.Control, v.Step = "number", "any"
			case form.Email:
				v.Control = "email"
			case form.Phone:
				v.Control = "tel"
			case form.Password:
				v.Control, v.Value = "password", "" // never sent back to the browser
			default:
				v.Control = "text"
			}
		}
		out = append(out, v)
	}
	return out
}

func fmtBound(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func maxLen(f form.Field) int {
	if f.MaxLen > 0 {
		return f.MaxLen
	}
	if f.Kind == form.MultiLine {
		return form.DefaultMaxMulti
	}
	return form.DefaultMaxSingle
}

// formValues reads fm's fields from a parsed POST: an unticked box is
// false and several ticked choices are joined with commas, as form.Values
// stores them.
func formValues(fm *form.Form, r *http.Request) form.Values {
	vals := form.Values{}
	for _, f := range fm.Fields {
		name := fieldPrefix + f.Name
		switch {
		case f.Kind == form.Boolean:
			vals[f.Name] = form.False
			if r.PostForm.Get(name) == form.True {
				vals[f.Name] = form.True
			}
		case f.Kind == form.Choice && f.Multi:
			vals[f.Name] = strings.Join(r.PostForm[name], ",")
		default:
			vals[f.Name] = r.PostForm.Get(name)
		}
	}
	return vals
}
