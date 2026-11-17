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

// WebError makes the web server answer with Status and show Message to the
// member (e.g. a rejected form). Message must be safe to show.
type WebError struct {
	Status  int
	Message string
}

func (e *WebError) Error() string { return e.Message }

// WebRoute is a page or action a plugin adds to the web interface. It is
// served under /p/<plugin id>/ to members who are logged in and hold one of
// AnyOf (or any member if AnyOf is empty).
//
// Exactly one of Handle and Stream is set:
//   - Handle with Method "" or "GET" returns a page shown inside the layout.
//   - Handle with Method "POST" performs an action. The core checks the
//     session's CSRF token (form field "csrf") and the request origin
//     before calling it; the result must set WebPage.Redirect.
//   - Stream (GET only) serves a long-lived response such as server-sent
//     events. The core lifts the usual timeouts, ends the request when the
//     session expires, is revoked or the server shuts down, and limits how
//     many streams one member may hold open.
type WebRoute struct {
	// Path is relative to /p/<plugin id>, e.g. "/" or "/thread/{id}".
	Path string
	// Method is "GET" (the default) or "POST".
	Method string
	// Nav, if set, adds the page to the site navigation under this label.
	Nav   string
	AnyOf []string
	// Handle returns the page. Body must be built with html/template so
	// everything in it is escaped.
	Handle func(r *http.Request, s WebSession) (WebPage, error)
	// Stream writes the response itself until r.Context() is done. Return
	// ErrWebNotFound before writing anything to answer 404.
	Stream func(w http.ResponseWriter, r *http.Request, s WebSession) error
}

// WebSession is the logged-in member as seen by a plugin web page.
type WebSession interface {
	UserID() int64
	Permissions(ctx context.Context) (perm.Set, error)
	// Markdown renders markdown as sanitised HTML with graded links.
	Markdown(src string) template.HTML
	// Path returns the URL of another page of the same plugin.
	Path(rel string) string
	// CSRF is the token POST forms must send in a field named "csrf".
	CSRF() string
}

// WebPage is a plugin page's content, shown inside the site layout.
type WebPage struct {
	Title string
	Body  template.HTML
	// Redirect, for POST routes, is the local path to send the browser to
	// afterwards (e.g. back to the page holding the form). Anything that is
	// not a plain local path is replaced by /home.
	Redirect string
}
