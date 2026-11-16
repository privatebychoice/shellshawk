package plugin

import (
	"context"
	"errors"
	"html/template"
	"net/http"

	"go.privatebychoice.com/shellshawk/internal/perm"
)

// ErrWebNotFound makes the web server answer 404 for a plugin page.
var ErrWebNotFound = errors.New("not found")

// WebRoute is a page a plugin adds to the web interface. It is served under
// /p/<plugin id>/ to members who are logged in and hold one of AnyOf (or
// any member if AnyOf is empty). Only GET is supported: the web interface
// is read-only in this version.
type WebRoute struct {
	// Path is relative to /p/<plugin id>, e.g. "/" or "/thread/{id}".
	Path string
	// Nav, if set, adds the page to the site navigation under this label.
	Nav   string
	AnyOf []string
	// Handle returns the page. Body must be built with html/template so
	// everything in it is escaped.
	Handle func(r *http.Request, s WebSession) (WebPage, error)
}

// WebSession is the logged-in member as seen by a plugin web page.
type WebSession interface {
	UserID() int64
	Permissions(ctx context.Context) (perm.Set, error)
	// Markdown renders markdown as sanitised HTML with graded links.
	Markdown(src string) template.HTML
	// Path returns the URL of another page of the same plugin.
	Path(rel string) string
}

// WebPage is a plugin page's content, shown inside the site layout.
type WebPage struct {
	Title string
	Body  template.HTML
}
