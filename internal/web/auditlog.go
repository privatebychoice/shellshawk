package web

import (
	"net/http"
	"strconv"
	"time"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/perm"
)

// The audit log, read-only, for holders of core.audit.view.

const auditPageSize = 100

type auditRow struct {
	ISO, When, Actor, Action, Target, Detail string
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.requirePerm(w, r, perm.AuditView, "You do not have permission to read the audit log.") == nil {
		return
	}
	var before int64
	if raw := r.URL.Query().Get("before"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n <= 0 {
			s.renderError(w, r, http.StatusBadRequest, "That page of the audit log does not exist.")
			return
		}
		before = n
	}
	// One extra entry tells whether there is an older page.
	recs, err := audit.Before(r.Context(), s.cfg.Auth.DB(), before, auditPageSize+1)
	if err != nil {
		LoggerFrom(r.Context()).Error("read audit log", "err", err)
		s.renderError(w, r, http.StatusInternalServerError, "The audit log could not be read. Please try again.")
		return
	}
	var older int64
	if len(recs) > auditPageSize {
		recs = recs[:auditPageSize]
		older = recs[len(recs)-1].ID
	}
	rows := make([]auditRow, 0, len(recs))
	for _, rec := range recs {
		target := rec.TargetType
		if rec.TargetID != "" {
			target += " " + rec.TargetID
		}
		rows = append(rows, auditRow{
			ISO: rec.At.UTC().Format(time.RFC3339), When: rec.At.UTC().Format("2006-01-02 15:04"),
			Actor: rec.Actor, Action: rec.Action, Target: target, Detail: rec.Detail,
		})
	}
	s.render(w, r, http.StatusOK, "Audit log", "audit", map[string]any{
		"Rows": rows, "Before": before, "Older": older, "PageSize": auditPageSize, "Days": s.cfg.AuditDays,
	})
}
