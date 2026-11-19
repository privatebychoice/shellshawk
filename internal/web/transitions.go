package web

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/transition"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Transition screens, for holders of core.transitions.manage: the same
// profiles, files and transition points as Administration → Transitions
// and SFTP /text. transition.Service re-checks the permission, validates
// and cleans every file, and audits each change.

// maxArtFormBytes bounds a request carrying a file: the largest file,
// URL-encoded (up to three bytes for each), plus the other fields.
const maxArtFormBytes = 3*transition.MaxFileBytes + 8<<10

var transitionNotices = map[string]string{
	"created":  "The profile has been created. Add files below.",
	"saved":    "The profile has been saved.",
	"uploaded": "The file has been uploaded.",
	"written":  "The file has been saved.",
	"removed":  "The file has been deleted.",
	"deleted":  "The profile has been deleted. Places that showed it now use the default.",
	"points":   "Where transitions are shown has been saved.",
}

func (s *Server) transitionsEnabled() bool { return s.cfg.Transitions != nil && s.cfg.MenuItems != nil }

func (s *Server) transitionAdmin(w http.ResponseWriter, r *http.Request) *websess.Session {
	return s.requirePerm(w, r, perm.TransitionsManage, "You do not have permission to manage transition screens.")
}

// transitionPost checks a POST's session and token. limit bounds the body.
func (s *Server) transitionPost(w http.ResponseWriter, r *http.Request, limit int64) *websess.Session {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	sess := s.transitionAdmin(w, r)
	if sess == nil {
		return nil
	}
	var err error
	if limit > maxFormBytes && r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		err = r.ParseMultipartForm(limit)
	} else {
		err = r.ParseForm()
	}
	var tooBig *http.MaxBytesError
	if errors.As(err, &tooBig) {
		s.renderError(w, r, http.StatusRequestEntityTooLarge, fmt.Sprintf("That is too big. Files can be at most %d KiB.", transition.MaxFileBytes>>10))
		return nil
	}
	if err != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return nil
	}
	return sess
}

func (s *Server) transitionFailure(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, perm.ErrForbidden):
		s.renderError(w, r, http.StatusForbidden, "You do not have permission to manage transition screens.")
	case errors.Is(err, transition.ErrNotFound):
		s.renderError(w, r, http.StatusNotFound, "That profile or file does not exist. It may have been deleted meanwhile.")
	default:
		LoggerFrom(r.Context()).Error("transitions", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
	}
}

// refusal returns the message and status for an error the person can fix,
// or "" for anything else.
func refusal(err error) (string, int) {
	switch {
	case errors.Is(err, transition.ErrExists):
		return transition.Reason(err), http.StatusConflict
	case errors.Is(err, transition.ErrInvalid), errors.Is(err, transition.ErrTooMany):
		return transition.Reason(err), http.StatusUnprocessableEntity
	}
	return "", 0
}

func profileShows(p transition.Profile) string {
	if p.Mode == transition.ModeSingle && p.File != "" {
		return "always " + p.File
	}
	return "a random file each time"
}

// ---- the overview ------------------------------------------------------------

type pointOption struct {
	Value, Label string
	Selected     bool
}

type pointRow struct {
	Target, Label string
	Enter, Exit   []pointOption
}

func pointField(moment, target string) string { return moment + "/" + target }

func (s *Server) pointTargets() (targets []string, labels map[string]string) {
	labels = map[string]string{transition.DefaultTarget: "Default for every item"}
	targets = []string{transition.DefaultTarget}
	for _, d := range s.cfg.MenuItems.MenuDefaults() {
		targets = append(targets, d.Target)
		labels[d.Target] = d.Label
	}
	return targets, labels
}

// pointChoice is a transition point's current setting as a form value.
func pointChoice(pts map[string]transition.Point, target, moment string) string {
	pt := pts[transition.PointKey(target, moment)]
	switch {
	case !pt.Set && target == transition.DefaultTarget, pt.Set && pt.ProfileID == 0:
		return "none"
	case !pt.Set:
		return "inherit"
	}
	return strconv.FormatInt(pt.ProfileID, 10)
}

func pointOptions(profiles []transition.Profile, isDefault bool, selected string) []pointOption {
	var out []pointOption
	if !isDefault {
		out = append(out, pointOption{Value: "inherit", Label: "The default"})
	}
	out = append(out, pointOption{Value: "none", Label: "Nothing"})
	for _, p := range profiles {
		out = append(out, pointOption{Value: strconv.FormatInt(p.ID, 10), Label: p.Slug})
	}
	for i := range out {
		out[i].Selected = out[i].Value == selected
	}
	return out
}

func (s *Server) renderTransitions(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, newSlug, newErr, pointsErr string) {
	ctx := r.Context()
	profiles, err := s.cfg.Transitions.Profiles(ctx)
	if err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	pts, err := s.cfg.Transitions.Points(ctx)
	if err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	targets, labels := s.pointTargets()
	rows := make([]pointRow, 0, len(targets))
	for _, t := range targets {
		isDefault := t == transition.DefaultTarget
		rows = append(rows, pointRow{Target: t, Label: labels[t],
			Enter: pointOptions(profiles, isDefault, pointChoice(pts, t, transition.Enter)),
			Exit:  pointOptions(profiles, isDefault, pointChoice(pts, t, transition.Exit))})
	}
	type profileRow struct {
		transition.Profile
		Shows string
	}
	prows := make([]profileRow, 0, len(profiles))
	for _, p := range profiles {
		prows = append(prows, profileRow{p, profileShows(p)})
	}
	s.render(w, r, status, "Transitions", "transitions", map[string]any{
		"Profiles": prows, "Points": rows, "CSRF": sess.CSRF, "Notice": transitionNotices[r.URL.Query().Get("done")],
		"NewSlug": newSlug, "NewError": newErr, "PointsError": pointsErr, "MaxSlug": transition.MaxSlugLen,
	})
}

func (s *Server) handleTransitions(w http.ResponseWriter, r *http.Request) {
	if sess := s.transitionAdmin(w, r); sess != nil {
		s.renderTransitions(w, r, http.StatusOK, sess, "", "", "")
	}
}

func (s *Server) handleTransitionCreate(w http.ResponseWriter, r *http.Request) {
	sess := s.transitionPost(w, r, maxFormBytes)
	if sess == nil {
		return
	}
	slug := r.PostForm.Get("slug")
	id, err := s.cfg.Transitions.CreateProfile(r.Context(), sess.UserID, slug)
	if err != nil {
		if msg, status := refusal(err); msg != "" {
			s.renderTransitions(w, r, status, sess, slug, msg, "")
			return
		}
		s.transitionFailure(w, r, err)
		return
	}
	LoggerFrom(r.Context()).Info("transition profile created from the web", "actor", sess.UserID, "profile_id", id)
	http.Redirect(w, r, "/admin/transitions/"+strconv.FormatInt(id, 10)+"?done=created", http.StatusSeeOther)
}

// handleTransitionPoints saves every transition point whose choice
// changed.
func (s *Server) handleTransitionPoints(w http.ResponseWriter, r *http.Request) {
	sess := s.transitionPost(w, r, maxFormBytes)
	if sess == nil {
		return
	}
	ctx := r.Context()
	profiles, err := s.cfg.Transitions.Profiles(ctx)
	if err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	pts, err := s.cfg.Transitions.Points(ctx)
	if err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	type change struct {
		target, moment string
		c              transition.Choice
	}
	var changes []change
	targets, _ := s.pointTargets()
	for _, t := range targets {
		for _, m := range []string{transition.Enter, transition.Exit} {
			v := r.PostForm.Get(pointField(m, t))
			if v == "" || v == pointChoice(pts, t, m) {
				continue // not sent, or unchanged
			}
			valid := false
			for _, o := range pointOptions(profiles, t == transition.DefaultTarget, "") {
				valid = valid || o.Value == v
			}
			if !valid {
				s.renderTransitions(w, r, http.StatusUnprocessableEntity, sess, "", "", "A choice was not one of those offered. Nothing was saved; check the choices and try again.")
				return
			}
			c := transition.Choice{Inherit: v == "inherit"}
			if v != "inherit" && v != "none" {
				c.ProfileID, _ = strconv.ParseInt(v, 10, 64)
			}
			changes = append(changes, change{t, m, c})
		}
	}
	for _, ch := range changes {
		err := s.cfg.Transitions.SetPoint(ctx, sess.UserID, ch.target, ch.moment, ch.c, s.cfg.MenuItems.ItemExists)
		if errors.Is(err, transition.ErrNotFound) {
			s.renderTransitions(w, r, http.StatusConflict, sess, "", "", "A profile was deleted meanwhile. Check the choices and save again.")
			return
		}
		if err != nil {
			s.transitionFailure(w, r, err)
			return
		}
	}
	LoggerFrom(ctx).Info("transition points saved from the web", "actor", sess.UserID, "changed", len(changes))
	http.Redirect(w, r, "/admin/transitions?done=points", http.StatusSeeOther)
}

// ---- a profile ---------------------------------------------------------------

// profile loads the profile named in the path.
func (s *Server) profile(w http.ResponseWriter, r *http.Request) (transition.Profile, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		if p, err := s.cfg.Transitions.ProfileByID(r.Context(), id); err == nil {
			return p, true
		}
	}
	s.renderError(w, r, http.StatusNotFound, "That profile does not exist.")
	return transition.Profile{}, false
}

func profileForm(files []transition.File) *form.Form {
	opts := make([]form.Option, 0, len(files))
	for _, f := range files {
		opts = append(opts, form.Option{Value: f.Name, Label: f.Name})
	}
	return &form.Form{Fields: []form.Field{
		{Name: "slug", Label: "Name", Kind: form.SingleLine, Required: true, MaxLen: transition.MaxSlugLen,
			Help: "Lowercase letters, digits and hyphens. It is also the SFTP folder, /text/<name>/."},
		{Name: "mode", Label: "Show", Kind: form.Choice, Required: true, Options: []form.Option{
			{Value: transition.ModeRandom, Label: "A random file each time"},
			{Value: transition.ModeSingle, Label: "Always the file chosen below"},
		}},
		{Name: "file", Label: "File to show", Kind: form.Choice, Options: opts, Help: "Used only when the profile always shows one file."},
	}}
}

// profilePage is what the profile page shows besides the profile itself:
// values and errors of a form sent back.
type profilePage struct {
	status                    int
	vals                      form.Values
	errs                      form.Errors
	settingsErr               string
	writeName, writeText      string
	writeErr, uploadErr       string
	deleteErr, writeNameError string
}

func (s *Server) renderProfile(w http.ResponseWriter, r *http.Request, sess *websess.Session, p transition.Profile, pg profilePage) {
	files, err := s.cfg.Transitions.Files(r.Context(), p.ID)
	if err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	vals := pg.vals
	if vals == nil {
		vals = form.Values{"slug": p.Slug, "mode": p.Mode, "file": p.File}
	}
	if pg.status == 0 {
		pg.status = http.StatusOK
	}
	s.render(w, r, pg.status, "Transition profile "+p.Slug, "transition", map[string]any{
		"ID": p.ID, "Slug": p.Slug, "Shows": profileShows(p), "Files": files, "CSRF": sess.CSRF,
		"Notice": transitionNotices[r.URL.Query().Get("done")], "Fields": fieldViews(profileForm(files), vals, pg.errs),
		"SettingsError": pg.settingsErr, "WriteName": pg.writeName, "WriteText": pg.writeText, "WriteError": pg.writeErr,
		"WriteNameError": pg.writeNameError, "UploadError": pg.uploadErr, "DeleteError": pg.deleteErr,
		"MaxName": transition.MaxNameLen, "MaxKiB": transition.MaxFileBytes >> 10, "MaxFiles": transition.MaxFiles,
	})
}

func (s *Server) handleTransitionProfile(w http.ResponseWriter, r *http.Request) {
	sess := s.transitionAdmin(w, r)
	if sess == nil {
		return
	}
	if p, ok := s.profile(w, r); ok {
		s.renderProfile(w, r, sess, p, profilePage{})
	}
}

// profileDone redirects to the profile's page with a fixed notice.
func (s *Server) profileDone(w http.ResponseWriter, r *http.Request, sess *websess.Session, id int64, done string) {
	LoggerFrom(r.Context()).Info("transition profile changed from the web", "actor", sess.UserID, "profile_id", id, "change", done)
	http.Redirect(w, r, "/admin/transitions/"+strconv.FormatInt(id, 10)+"?done="+done, http.StatusSeeOther)
}

func (s *Server) handleTransitionProfileSave(w http.ResponseWriter, r *http.Request) {
	sess := s.transitionPost(w, r, maxFormBytes)
	if sess == nil {
		return
	}
	p, ok := s.profile(w, r)
	if !ok {
		return
	}
	files, err := s.cfg.Transitions.Files(r.Context(), p.ID)
	if err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	fm := profileForm(files)
	raw := formValues(fm, r)
	vals, errs := fm.Validate(raw)
	if len(errs) == 0 {
		if vals["mode"] == transition.ModeSingle && vals["file"] == "" {
			errs = form.Errors{"file": errors.New("choose the file to show")}
		} else if err := transition.CheckSlug(vals["slug"]); err != nil {
			errs = form.Errors{"slug": errors.New(transition.Reason(err))}
		}
	}
	if len(errs) == 0 {
		err := s.cfg.Transitions.UpdateProfile(r.Context(), sess.UserID, p.ID, vals["slug"], vals["mode"], vals["file"])
		switch {
		case err == nil:
			s.profileDone(w, r, sess, p.ID, "saved")
			return
		case errors.Is(err, transition.ErrExists):
			errs = form.Errors{"slug": errors.New(transition.Reason(err))}
		case errors.Is(err, transition.ErrInvalid):
			errs = form.Errors{"file": errors.New(transition.Reason(err))}
		default:
			s.transitionFailure(w, r, err)
			return
		}
	}
	s.renderProfile(w, r, sess, p, profilePage{status: http.StatusUnprocessableEntity, vals: raw, errs: errs,
		settingsErr: "The profile was not saved. Correct the fields marked below."})
}

func (s *Server) handleTransitionUpload(w http.ResponseWriter, r *http.Request) {
	sess := s.transitionPost(w, r, maxArtFormBytes)
	if sess == nil {
		return
	}
	p, ok := s.profile(w, r)
	if !ok {
		return
	}
	fail := func(msg string) {
		s.renderProfile(w, r, sess, p, profilePage{status: http.StatusUnprocessableEntity, uploadErr: msg})
	}
	f, hdr, err := r.FormFile("file")
	if err != nil {
		fail("Choose a file to upload.")
		return
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, transition.MaxFileBytes+1))
	if err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	name := r.PostForm.Get("name")
	if name == "" {
		name = path.Base(hdr.Filename)
	}
	if err := transition.CheckName(name); err != nil {
		fail("The file name is not allowed. " + transition.Reason(err) + " Give it a name in the field above.")
		return
	}
	err = s.cfg.Transitions.SaveFile(r.Context(), sess.UserID, p.ID, name, data)
	if msg, _ := refusal(err); msg != "" {
		fail(msg)
		return
	}
	if err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	s.profileDone(w, r, sess, p.ID, "uploaded")
}

func (s *Server) handleTransitionWrite(w http.ResponseWriter, r *http.Request) {
	sess := s.transitionPost(w, r, maxArtFormBytes)
	if sess == nil {
		return
	}
	p, ok := s.profile(w, r)
	if !ok {
		return
	}
	name, text := r.PostForm.Get("name"), r.PostForm.Get("text")
	pg := profilePage{status: http.StatusUnprocessableEntity, writeName: name, writeText: text}
	if err := transition.CheckName(name); err != nil {
		pg.writeNameError = transition.Reason(err)
	} else if _, _, err := s.cfg.Transitions.ReadFile(r.Context(), p.ID, name); err == nil {
		pg.status, pg.writeNameError = http.StatusConflict, "A file with that name exists. Open it from the list to edit it."
	}
	if pg.writeNameError != "" {
		pg.writeErr = "The file was not saved. Correct the name."
		s.renderProfile(w, r, sess, p, pg)
		return
	}
	err := s.cfg.Transitions.SaveFile(r.Context(), sess.UserID, p.ID, name, []byte(text))
	if msg, status := refusal(err); msg != "" {
		pg.status, pg.writeErr = status, "The file was not saved. "+msg
		s.renderProfile(w, r, sess, p, pg)
		return
	}
	if err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin/transitions/"+strconv.FormatInt(p.ID, 10)+"/files/"+name+"?done=written", http.StatusSeeOther)
}

func (s *Server) handleTransitionDelete(w http.ResponseWriter, r *http.Request) {
	sess := s.transitionPost(w, r, maxFormBytes)
	if sess == nil {
		return
	}
	p, ok := s.profile(w, r)
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != "yes" {
		s.renderProfile(w, r, sess, p, profilePage{status: http.StatusUnprocessableEntity, deleteErr: "Tick the box to confirm, then try again."})
		return
	}
	if err := s.cfg.Transitions.DeleteProfile(r.Context(), sess.UserID, p.ID, false); err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	LoggerFrom(r.Context()).Info("transition profile deleted from the web", "actor", sess.UserID, "profile_id", p.ID)
	http.Redirect(w, r, "/admin/transitions?done=deleted", http.StatusSeeOther)
}

// ---- a file ------------------------------------------------------------------

func (s *Server) renderArtFile(w http.ResponseWriter, r *http.Request, sess *websess.Session, p transition.Profile, name string, status int, text, editErr, deleteErr string) {
	saved, updated, err := s.cfg.Transitions.ReadFile(r.Context(), p.ID, name)
	if err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	if text == "" {
		text = saved
	}
	s.render(w, r, status, p.Slug+"/"+name, "transition-file", map[string]any{
		"ID": p.ID, "Slug": p.Slug, "Name": name, "Saved": saved, "Text": text, "Updated": updated,
		"CSRF": sess.CSRF, "Notice": transitionNotices[r.URL.Query().Get("done")], "EditError": editErr, "DeleteError": deleteErr,
		"MaxKiB": transition.MaxFileBytes >> 10,
	})
}

func (s *Server) handleTransitionFile(w http.ResponseWriter, r *http.Request) {
	sess := s.transitionAdmin(w, r)
	if sess == nil {
		return
	}
	if p, ok := s.profile(w, r); ok {
		s.renderArtFile(w, r, sess, p, r.PathValue("name"), http.StatusOK, "", "", "")
	}
}

func (s *Server) handleTransitionFileSave(w http.ResponseWriter, r *http.Request) {
	sess := s.transitionPost(w, r, maxArtFormBytes)
	if sess == nil {
		return
	}
	p, ok := s.profile(w, r)
	if !ok {
		return
	}
	name, text := r.PathValue("name"), r.PostForm.Get("text")
	if _, _, err := s.cfg.Transitions.ReadFile(r.Context(), p.ID, name); err != nil {
		s.transitionFailure(w, r, err) // saving here edits; it never creates a file
		return
	}
	err := s.cfg.Transitions.SaveFile(r.Context(), sess.UserID, p.ID, name, []byte(text))
	if msg, status := refusal(err); msg != "" {
		s.renderArtFile(w, r, sess, p, name, status, text, "The file was not saved. "+msg, "")
		return
	}
	if err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	LoggerFrom(r.Context()).Info("transition file saved from the web", "actor", sess.UserID, "profile_id", p.ID)
	http.Redirect(w, r, "/admin/transitions/"+strconv.FormatInt(p.ID, 10)+"/files/"+name+"?done=written", http.StatusSeeOther)
}

func (s *Server) handleTransitionFileDelete(w http.ResponseWriter, r *http.Request) {
	sess := s.transitionPost(w, r, maxFormBytes)
	if sess == nil {
		return
	}
	p, ok := s.profile(w, r)
	if !ok {
		return
	}
	name := r.PathValue("name")
	if r.PostForm.Get("confirm") != "yes" {
		s.renderArtFile(w, r, sess, p, name, http.StatusUnprocessableEntity, "", "", "Tick the box to confirm, then try again.")
		return
	}
	if err := s.cfg.Transitions.DeleteFile(r.Context(), sess.UserID, p.ID, name); err != nil {
		s.transitionFailure(w, r, err)
		return
	}
	s.profileDone(w, r, sess, p.ID, "removed")
}
