package web

import (
	"errors"
	"net/http"

	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/websess"
)

// Plugin settings: the settings each plugin declares, for holders of
// core.plugins.settings. plugin.Settings.Save validates every field and
// re-checks the permission.

// maxSettingsFormBytes allows a multi-line setting at its default limit.
const maxSettingsFormBytes = 128 << 10

func (s *Server) pluginStaff(w http.ResponseWriter, r *http.Request) *websess.Session {
	sess := sessionFrom(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return nil
	}
	if ok, err := s.cfg.Perms.Has(r.Context(), sess.UserID, perm.PluginSettings); err != nil || !ok {
		s.renderError(w, r, http.StatusForbidden, "You do not have permission to change plugin settings.")
		return nil
	}
	return sess
}

// configurable returns the plugins that declare settings.
func (s *Server) configurable() []*plugin.Loaded {
	if s.cfg.Plugins == nil {
		return nil
	}
	var out []*plugin.Loaded
	for _, p := range s.cfg.Plugins.Plugins() {
		if len(p.Settings.Defs()) > 0 {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) configurablePlugin(id string) *plugin.Loaded {
	for _, p := range s.configurable() {
		if p.Manifest.ID == id {
			return p
		}
	}
	return nil
}

func (s *Server) handlePluginSettingsList(w http.ResponseWriter, r *http.Request) {
	if s.pluginStaff(w, r) == nil {
		return
	}
	type item struct{ ID, Name, Description string }
	var items []item
	for _, p := range s.configurable() {
		items = append(items, item{p.Manifest.ID, p.Manifest.Name, p.Manifest.Description})
	}
	s.render(w, r, http.StatusOK, "Plugin settings", "plugin-settings-list", map[string]any{"Plugins": items})
}

func (s *Server) renderPluginSettings(w http.ResponseWriter, r *http.Request, status int, sess *websess.Session, p *plugin.Loaded, vals form.Values, errs form.Errors, notice string) {
	s.render(w, r, status, p.Manifest.Name+" settings", "plugin-settings", map[string]any{
		"ID": p.Manifest.ID, "CSRF": sess.CSRF, "Notice": notice, "Invalid": len(errs) > 0,
		"Fields": fieldViews(p.Settings.Form(""), vals, errs),
	})
}

func (s *Server) handlePluginSettings(w http.ResponseWriter, r *http.Request) {
	sess := s.pluginStaff(w, r)
	if sess == nil {
		return
	}
	p := s.configurablePlugin(r.PathValue("id"))
	if p == nil {
		s.renderError(w, r, http.StatusNotFound, "That plugin has no settings.")
		return
	}
	vals, err := p.Settings.All(r.Context())
	if err != nil {
		LoggerFrom(r.Context()).Error("read plugin settings", "plugin", p.Manifest.ID, "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "The settings could not be read. Please try again.")
		return
	}
	notice := ""
	if r.URL.Query().Get("done") == "saved" {
		notice = "Settings saved."
	}
	s.renderPluginSettings(w, r, http.StatusOK, sess, p, vals, nil, notice)
}

func (s *Server) handlePluginSettingsSave(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSettingsFormBytes)
	sess := s.pluginStaff(w, r)
	if sess == nil {
		return
	}
	if r.ParseForm() != nil || !websess.CheckCSRF(*sess, r.PostForm.Get("csrf")) {
		s.renderError(w, r, http.StatusForbidden, "Your session has ended. Please log in again.")
		return
	}
	p := s.configurablePlugin(r.PathValue("id"))
	if p == nil {
		s.renderError(w, r, http.StatusNotFound, "That plugin has no settings.")
		return
	}
	vals := formValues(p.Settings.Form(""), r)
	errs, err := p.Settings.Save(r.Context(), sess.UserID, vals)
	switch {
	case errors.Is(err, perm.ErrForbidden):
		s.renderError(w, r, http.StatusForbidden, "You do not have permission to change plugin settings.")
	case err != nil:
		LoggerFrom(r.Context()).Error("save plugin settings", "plugin", p.Manifest.ID, "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "The settings could not be saved. Please try again.")
	case len(errs) > 0:
		s.renderPluginSettings(w, r, http.StatusUnprocessableEntity, sess, p, vals, errs, "")
	default:
		LoggerFrom(r.Context()).Info("plugin settings changed from the web", "plugin", p.Manifest.ID, "actor", sess.UserID)
		http.Redirect(w, r, "/admin/plugins/"+p.Manifest.ID+"?done=saved", http.StatusSeeOther)
	}
}
