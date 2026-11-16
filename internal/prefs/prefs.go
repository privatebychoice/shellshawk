// Package prefs stores per-user display preferences: terminal profile,
// theme, emphasis overrides and accessibility options.
package prefs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"go.privatebychoice.com/shellshawk/internal/store"
	"go.privatebychoice.com/shellshawk/internal/theme"
)

// Page size limits for line mode.
const (
	MinPageSize     = 5
	MaxPageSize     = 200
	DefaultPageSize = 20
)

// Prefs are a user's display preferences.
type Prefs struct {
	Profile   string
	Theme     string
	Bold      theme.Emphasis // "" = profile default
	Italic    theme.Emphasis // "" = profile default
	ASCIIOnly bool
	PageSize  int
}

// Default returns the preferences for a user who has not set any.
func Default() Prefs {
	return Prefs{Profile: theme.DefaultProfile, Theme: theme.DefaultTheme, PageSize: DefaultPageSize}
}

// ErrInvalid is returned for preferences that name unknown profiles,
// themes or emphasis modes.
var ErrInvalid = errors.New("invalid preferences")

// Service reads and writes preferences.
type Service struct {
	db     *sql.DB
	themes *theme.Catalog
	now    func() time.Time
}

// NewService returns a Service. now may be nil.
func NewService(db *sql.DB, themes *theme.Catalog, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, themes: themes, now: now}
}

// Validate checks p against the known profiles and themes.
func (s *Service) Validate(p Prefs) error {
	if _, ok := theme.LookupProfile(p.Profile); !ok {
		return fmt.Errorf("%w: unknown profile %q", ErrInvalid, p.Profile)
	}
	if s.themes.Get(p.Theme) == nil {
		return fmt.Errorf("%w: unknown theme %q", ErrInvalid, p.Theme)
	}
	for _, e := range []theme.Emphasis{p.Bold, p.Italic} {
		if e != "" && !theme.ValidEmphasis(e) {
			return fmt.Errorf("%w: unknown emphasis %q", ErrInvalid, e)
		}
	}
	if p.PageSize < MinPageSize || p.PageSize > MaxPageSize {
		return fmt.Errorf("%w: page size must be %d to %d", ErrInvalid, MinPageSize, MaxPageSize)
	}
	return nil
}

// Get returns userID's preferences, or the defaults if none are stored. A
// stored profile or theme that no longer exists falls back to the default.
func (s *Service) Get(ctx context.Context, userID int64) (Prefs, error) {
	var p Prefs
	var bold, italic string
	err := s.db.QueryRowContext(ctx, `SELECT profile, theme, bold, italic, ascii_only, page_size FROM user_prefs WHERE user_id = ?`, userID).
		Scan(&p.Profile, &p.Theme, &bold, &italic, &p.ASCIIOnly, &p.PageSize)
	if errors.Is(err, sql.ErrNoRows) {
		return Default(), nil
	}
	if err != nil {
		return Prefs{}, fmt.Errorf("prefs: get: %w", err)
	}
	p.Bold, p.Italic = theme.Emphasis(bold), theme.Emphasis(italic)
	if _, ok := theme.LookupProfile(p.Profile); !ok {
		p.Profile = theme.DefaultProfile
	}
	if s.themes.Get(p.Theme) == nil {
		p.Theme = theme.DefaultTheme
	}
	return p, nil
}

// Set stores userID's preferences.
func (s *Service) Set(ctx context.Context, userID int64, p Prefs) error {
	if err := s.Validate(p); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO user_prefs (user_id, profile, theme, bold, italic, ascii_only, page_size, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET
			profile = excluded.profile, theme = excluded.theme, bold = excluded.bold, italic = excluded.italic,
			ascii_only = excluded.ascii_only, page_size = excluded.page_size, updated_at = excluded.updated_at`,
		userID, p.Profile, p.Theme, string(p.Bold), string(p.Italic), p.ASCIIOnly, p.PageSize, store.FormatTime(s.now()))
	if err != nil {
		return fmt.Errorf("prefs: set: %w", err)
	}
	return nil
}

// Styler builds the theme styler for p: the profile with any emphasis and
// ASCII overrides applied.
func (s *Service) Styler(p Prefs) theme.Styler {
	prof, ok := theme.LookupProfile(p.Profile)
	if !ok {
		prof, _ = theme.LookupProfile(theme.DefaultProfile)
	}
	if p.Bold != "" {
		prof.Bold = p.Bold
	}
	if p.Italic != "" {
		prof.Italic = p.Italic
	}
	if p.ASCIIOnly {
		prof.Unicode = false
	}
	th := s.themes.Get(p.Theme)
	if th == nil {
		th = s.themes.Get(theme.DefaultTheme)
	}
	return theme.Styler{Theme: th, Profile: prof}
}

// Themes returns the theme catalog.
func (s *Service) Themes() *theme.Catalog { return s.themes }
