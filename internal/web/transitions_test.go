package web

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/transition"
)

// upload posts a multipart form with one file to path.
func (e *env) upload(t *testing.T, cookie *http.Cookie, path, csrf, name, filename string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	var b bytes.Buffer
	mw := multipart.NewWriter(&b)
	mw.WriteField("csrf", csrf)
	mw.WriteField("name", name)
	if filename != "" {
		fw, _ := mw.CreateFormFile("file", filename)
		fw.Write(data)
	}
	mw.Close()
	q := httptest.NewRequest("POST", "http://bbs.example.net"+path, &b)
	q.Header.Set("Content-Type", mw.FormDataContentType())
	q.Header.Set("Origin", origin)
	q.AddCookie(cookie)
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, q)
	return rec
}

func TestTransitionsPages(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()

	// Members and moderators do not hold core.transitions.manage.
	for name, uid := range map[string]int64{"alice": e.alice, "mod1": e.mod} {
		c := e.login(t, uid, name)
		if home := e.do(req{method: "GET", path: "/home", cookie: c}).Body.String(); strings.Contains(home, `href="/admin/transitions"`) {
			t.Errorf("%s sees the Transitions link", name)
		}
		if rec := e.do(req{method: "GET", path: "/admin/transitions", cookie: c}); rec.Code != http.StatusForbidden {
			t.Errorf("%s = %d", name, rec.Code)
		}
	}

	admin := e.login(t, e.admin, "admin1")
	if home := e.do(req{method: "GET", path: "/home", cookie: admin}).Body.String(); !strings.Contains(home, `<a href="/admin/transitions">Transitions</a>`) {
		t.Error("admin nav missing the link")
	}
	page := e.do(req{method: "GET", path: "/admin/transitions", cookie: admin}).Body.String()
	for _, want := range []string{"There are no profiles yet.", `<th scope="row">Default for every item</th>`, `<th scope="row">Read notes</th>`,
		`<label class="visually-hidden" for="enter-1">When opening Administration</label><select id="enter-1" name="enter/core:admin">`,
		`<option value="inherit" selected>The default</option>`} {
		if !strings.Contains(page, want) {
			t.Errorf("overview missing %q", want)
		}
	}
	csrf := csrfFrom(t, page)
	post := func(path string, v url.Values) (int, string, string) {
		t.Helper()
		v.Set("csrf", csrf)
		rec := e.do(req{method: "POST", path: path, cookie: admin, origin: origin, form: v})
		return rec.Code, rec.Header().Get("Location"), rec.Body.String()
	}
	check := func(name string, st int, loc, body string, wantSt int, wantLoc, wantBody string) {
		t.Helper()
		if st != wantSt || loc != wantLoc || !strings.Contains(body, wantBody) {
			t.Errorf("%s = %d %q, want %d %q containing %q", name, st, loc, wantSt, wantLoc, wantBody)
		}
	}

	st, loc, body := post("/admin/transitions/new", url.Values{"slug": {"Bad Name"}})
	check("bad name", st, loc, body, 422, "", "The profile was not created. Use 1 to 40 lowercase letters")
	st, loc, _ = post("/admin/transitions/new", url.Values{"slug": {"welcome"}})
	p, err := e.trans.ProfileBySlug(ctx, "welcome")
	if err != nil {
		t.Fatal(err)
	}
	base := "/admin/transitions/" + strconv.FormatInt(p.ID, 10)
	check("create", st, loc, "", 303, base+"?done=created", "")
	st, loc, body = post("/admin/transitions/new", url.Values{"slug": {"welcome"}})
	check("duplicate", st, loc, body, 409, "", "A profile with that name already exists.")
	if b := e.do(req{method: "GET", path: base, cookie: admin}).Body.String(); !strings.Contains(b, "This profile has no files, so it shows nothing.") || !strings.Contains(b, "<code>/text/welcome/</code>") {
		t.Errorf("empty profile page:\n%s", b)
	}

	tests := []struct {
		name     string
		path     string
		form     url.Values
		status   int
		location string
		want     string
	}{
		{"write", base + "/write", url.Values{"name": {"logo.txt"}, "text": {"  /\\_/\\  \r\n ( o.o )"}}, 303, base + "/files/logo.txt?done=written", ""},
		{"write an existing name", base + "/write", url.Values{"name": {"logo.txt"}, "text": {"x"}}, 409, "", "A file with that name exists."},
		{"write a bad name", base + "/write", url.Values{"name": {"../x"}, "text": {"x"}}, 422, "", "Use 1 to 64 letters"},
		{"write no text", base + "/write", url.Values{"name": {"blank.txt"}, "text": {" \n "}}, 422, "", "The file was not saved. The file has no text."},
		{"edit", base + "/files/logo.txt", url.Values{"text": {"\x1b[31m( o.o )\x1b[0m"}}, 303, base + "/files/logo.txt?done=written", ""},
		{"edit a missing file", base + "/files/nope.txt", url.Values{"text": {"x"}}, 404, "", "does not exist"},
		{"single without a file", base, url.Values{"f-slug": {"welcome"}, "f-mode": {"single"}, "f-file": {""}}, 422, "", "choose the file to show"},
		{"single", base, url.Values{"f-slug": {"hello"}, "f-mode": {"single"}, "f-file": {"logo.txt"}}, 303, base + "?done=saved", ""},
		{"points: unknown choice", "/admin/transitions/points", url.Values{"enter/*": {"999"}}, 422, "", "A choice was not one of those offered."},
		{"points", "/admin/transitions/points", url.Values{"enter/*": {strconv.FormatInt(p.ID, 10)}, "exit/notes:read": {"none"}, "enter/notes:read": {"inherit"}},
			303, "/admin/transitions?done=points", ""},
		{"delete a file unconfirmed", base + "/files/logo.txt/delete", url.Values{}, 422, "", "Tick the box to confirm"},
		{"delete a profile unconfirmed", base + "/delete", url.Values{}, 422, "", "Tick the box to confirm"},
		{"unknown profile", "/admin/transitions/999/write", url.Values{"name": {"a.txt"}, "text": {"x"}}, 404, "", "That profile does not exist."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st, loc, body := post(tt.path, tt.form)
			if st != tt.status || loc != tt.location || !strings.Contains(body, tt.want) {
				t.Errorf("= %d %q, want %d %q containing %q\n%s", st, loc, tt.status, tt.location, tt.want, body)
			}
		})
	}
	if text, _, _ := e.trans.ReadFile(ctx, p.ID, "logo.txt"); text != "( o.o )" {
		t.Errorf("edited file = %q", text)
	}
	if p, _ = e.trans.ProfileByID(ctx, p.ID); p.Slug != "hello" || p.Mode != transition.ModeSingle || p.File != "logo.txt" {
		t.Errorf("profile = %+v", p)
	}
	if text, ok, _ := e.trans.Pick(ctx, "core:admin", transition.Enter); !ok || text != "( o.o )" {
		t.Errorf("default opening = %q, %v", text, ok)
	}
	if _, ok, _ := e.trans.Pick(ctx, "notes:read", transition.Exit); ok {
		t.Error("an item set to nothing shows something")
	}
	overview := e.do(req{method: "GET", path: "/admin/transitions", cookie: admin}).Body.String()
	if !strings.Contains(overview, `<option value="`+strconv.FormatInt(p.ID, 10)+`" selected>hello</option>`) ||
		!strings.Contains(overview, "always logo.txt") {
		t.Errorf("overview after saving:\n%s", overview)
	}
	file := e.do(req{method: "GET", path: base + "/files/logo.txt", cookie: admin}).Body.String()
	if !strings.Contains(file, `<pre class="art" tabindex="0" role="region" aria-label="Text art logo.txt">( o.o )</pre>`) {
		t.Errorf("file page:\n%s", file)
	}

	// Uploads: CP437 is decoded and the file's own name kept.
	uploads := []struct {
		name, saveAs, filename string
		data                   []byte
		status                 int
		want                   string
	}{
		{"cp437", "", "box.ans", []byte("\xc9\xcd\xbb\x1aSAUCE"), 303, ""},
		{"renamed", "frame.txt", "bad name.txt", []byte("frame"), 303, ""},
		{"bad file name", "", "bad name.txt", []byte("x"), 422, "The file name is not allowed."},
		{"no file", "x.txt", "", nil, 422, "Choose a file to upload."},
		{"too big", "", "big.txt", bytes.Repeat([]byte("x"), transition.MaxFileBytes+1), 422, "Files can be at most 64 KiB."},
		{"body too big", "", "huge.txt", bytes.Repeat([]byte("x"), 4*transition.MaxFileBytes), 413, "Files can be at most 64 KiB."},
	}
	for _, u := range uploads {
		t.Run("upload "+u.name, func(t *testing.T) {
			rec := e.upload(t, admin, base+"/upload", csrf, u.saveAs, u.filename, u.data)
			if rec.Code != u.status || !strings.Contains(rec.Body.String(), u.want) {
				t.Errorf("= %d, want %d containing %q\n%s", rec.Code, u.status, u.want, rec.Body.String())
			}
		})
	}
	if text, _, _ := e.trans.ReadFile(ctx, p.ID, "box.ans"); text != "╔═╗" {
		t.Errorf("uploaded file = %q", text)
	}
	if _, _, err := e.trans.ReadFile(ctx, p.ID, "frame.txt"); err != nil {
		t.Errorf("renamed upload: %v", err)
	}
	if rec := e.upload(t, admin, base+"/upload", "wrong", "", "a.txt", []byte("x")); rec.Code != http.StatusForbidden {
		t.Errorf("upload with a bad token = %d", rec.Code)
	}

	// Deleting a file, then the profile.
	st, loc, _ = post(base+"/files/logo.txt/delete", url.Values{"confirm": {"yes"}})
	check("delete a file", st, loc, "", 303, base+"?done=removed", "")
	if p, _ = e.trans.ProfileByID(ctx, p.ID); p.Mode != transition.ModeRandom {
		t.Errorf("deleting the chosen file left mode %q", p.Mode)
	}
	st, loc, _ = post(base+"/delete", url.Values{"confirm": {"yes"}})
	check("delete the profile", st, loc, "", 303, "/admin/transitions?done=deleted", "")
	if pts, _ := e.trans.Points(ctx); len(pts) != 1 { // only notes:read exit = nothing remains
		t.Errorf("points after deleting the profile = %+v", pts)
	}
	if rec := e.do(req{method: "GET", path: base, cookie: admin}); rec.Code != http.StatusNotFound {
		t.Errorf("deleted profile = %d", rec.Code)
	}
}
