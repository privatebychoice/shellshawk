package web

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"path"
	"sort"
	"strings"

	"go.privatebychoice.com/shellshawk/internal/theme"
)

//go:embed templates/*.html templates/*.md static/*
var files embed.FS

// asset is a static file served under a fingerprinted name, so a new
// release never meets a stale cached copy.
type asset struct {
	data        []byte
	contentType string
}

// Assets holds the fingerprinted URLs used by the templates.
type Assets struct {
	CSS, GPC, Theme string
}

type assetStore struct {
	byPath  map[string]asset
	themes  map[string]string // theme name → URL
	Default Assets
}

func fingerprint(name string, data []byte) string {
	sum := sha256.Sum256(data)
	ext := path.Ext(name)
	return "/static/" + strings.TrimSuffix(name, ext) + "." + hex.EncodeToString(sum[:])[:12] + ext
}

func (s *assetStore) add(name, contentType string, data []byte) string {
	p := fingerprint(name, data)
	s.byPath[p] = asset{data: data, contentType: contentType}
	return p
}

// themeCSS turns a theme into CSS custom properties: "title.fg" becomes
// --title-fg.
func themeCSS(th *theme.Theme) string {
	var names []string
	for t := range th.Colors {
		names = append(names, string(t))
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "--%s:%s;", strings.ReplaceAll(n, ".", "-"), th.Colors[theme.Token(n)].Hex())
	}
	scheme := "dark"
	if !th.Dark {
		scheme = "light"
	}
	return "color-scheme:" + scheme + ";" + b.String()
}

// loadAssets embeds the static files and builds one stylesheet per theme
// plus a default that follows the visitor's light/dark preference.
func loadAssets(cat *theme.Catalog) (*assetStore, error) {
	s := &assetStore{byPath: map[string]asset{}, themes: map[string]string{}}
	css, err := files.ReadFile("static/app.css")
	if err != nil {
		return nil, err
	}
	js, err := files.ReadFile("static/gpc.js")
	if err != nil {
		return nil, err
	}
	s.Default.CSS = s.add("app.css", "text/css; charset=utf-8", css)
	s.Default.GPC = s.add("gpc.js", "text/javascript; charset=utf-8", js)
	for _, th := range cat.All() {
		s.themes[th.Name] = s.add("theme-"+th.Name+".css", "text/css; charset=utf-8", []byte(":root{"+themeCSS(th)+"}\n"))
	}
	dark, light := cat.Get(theme.DefaultTheme), cat.Get("light")
	if dark == nil || light == nil {
		return nil, fmt.Errorf("web: default and light themes are required")
	}
	def := ":root{" + themeCSS(dark) + "}\n@media (prefers-color-scheme: light){:root{" + themeCSS(light) + "}}\n"
	s.Default.Theme = s.add("theme-default.css", "text/css; charset=utf-8", []byte(def))
	return s, nil
}

// forTheme returns the asset URLs for a member's chosen theme.
func (s *assetStore) forTheme(name string) Assets {
	a := s.Default
	if u, ok := s.themes[name]; ok {
		a.Theme = u
	}
	return a
}

func loadTemplates() (*template.Template, error) {
	return template.ParseFS(files, "templates/*.html")
}
