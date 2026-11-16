// Package linkgrade grades links with pbc-classification (the Privacy Badge
// Classification library) so every link shown in the BBS carries a privacy
// grade (docs/DESIGN.md §8.1). Classification is offline: no network
// requests are made.
package linkgrade

import (
	"fmt"
	"strings"

	classify "go.privatebychoice.com/pbc-classification"

	"go.privatebychoice.com/shellshawk/internal/theme"
)

// Result is a link's grade in display form.
type Result struct {
	Letter string      // "A".."F" or "?"
	Name   string      // e.g. "Considerate", "Unclassified"
	Token  theme.Token // theme colour for this grade
	Domain string      // registrable domain the URL resolved to, if any
}

// Label is "B Considerate".
func (r Result) Label() string { return r.Letter + " " + r.Name }

// Grader classifies URLs. It is safe for concurrent use.
type Grader struct {
	c *classify.Classifier
}

// New builds a Grader from the library's built-in dataset, optionally
// merged with a local JSON dataset (dataFile, "" for none), with the given
// domains treated as first-party (the BBS operator's own sites).
func New(dataFile string, firstParty []string) (*Grader, error) {
	var opts []classify.Option
	if dataFile != "" {
		opts = append(opts, classify.WithDataFile(dataFile))
	}
	if len(firstParty) > 0 {
		opts = append(opts, classify.WithFirstParty(firstParty...))
	}
	c, err := classify.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("linkgrade: %w", err)
	}
	return &Grader{c: c}, nil
}

// Grade classifies rawURL.
func (g *Grader) Grade(rawURL string) Result {
	cl := g.c.Classify(rawURL)
	return Result{Letter: cl.Grade.Letter(), Name: cl.Grade.Name(), Token: TokenFor(cl.Grade.Letter()), Domain: cl.Domain}
}

// TokenFor maps a grade letter to its theme colour token.
func TokenFor(letter string) theme.Token {
	switch strings.ToUpper(letter) {
	case "A":
		return theme.GradeA
	case "B":
		return theme.GradeB
	case "C":
		return theme.GradeC
	case "D":
		return theme.GradeD
	case "F":
		return theme.GradeF
	}
	return theme.GradeUnknown
}
