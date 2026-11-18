package web

import (
	"context"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.privatebychoice.com/shellshawk/internal/audit"
)

func TestAuditLogPage(t *testing.T) {
	e := setup(t, false)
	ctx := context.Background()
	db := e.srv.cfg.Auth.DB()
	// Setup already audited the registrations; clear them for exact counts.
	if _, err := db.Exec(`DELETE FROM audit_log`); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 11, 1, 9, 30, 0, 0, time.UTC)
	const total = auditPageSize + 5
	for i := range total {
		en := audit.Entry{Actor: e.admin, Action: "test.action", TargetType: "user", TargetID: e.alice, Detail: "entry " + strconv.Itoa(i)}
		if i == total-1 {
			en = audit.Entry{Actor: audit.SystemActor, Action: "test.newest", Detail: "<script>x</script>"}
		}
		if err := audit.Record(ctx, db, base.Add(time.Duration(i)*time.Minute), en); err != nil {
			t.Fatal(err)
		}
	}

	// Members without core.audit.view: no link, page refused.
	mod := e.login(t, e.mod, "mod1")
	if home := e.do(req{method: "GET", path: "/home", cookie: mod}).Body.String(); strings.Contains(home, "/admin/audit") {
		t.Error("moderator sees the Audit log link")
	}
	if rec := e.do(req{method: "GET", path: "/admin/audit", cookie: mod}); rec.Code != http.StatusForbidden {
		t.Errorf("moderator = %d", rec.Code)
	}

	admin := e.login(t, e.admin, "admin1")
	if home := e.do(req{method: "GET", path: "/home", cookie: admin}).Body.String(); !strings.Contains(home, `<a href="/admin/audit">Audit log</a>`) {
		t.Error("admin nav missing the link")
	}
	// The admin's login above is not audited, so counts stay exact.
	first := e.do(req{method: "GET", path: "/admin/audit", cookie: admin}).Body.String()
	rows := strings.Count(first, "<tr><td><time")
	newest := `<tr><td><time datetime="2026-11-01T11:14:00Z">2026-11-01 11:14</time></td><td>system</td><th scope="row">test.newest</th><td></td><td>&lt;script&gt;x&lt;/script&gt;</td></tr>`
	if rows != auditPageSize || !strings.Contains(first, newest) || !strings.Contains(first, "Entries are kept for 365 days.") ||
		!strings.Contains(first, `<td>admin1</td><th scope="row">test.action</th><td>user `+strconv.FormatInt(e.alice, 10)+`</td><td>entry 103</td>`) {
		t.Errorf("first page: %d rows:\n%s", rows, first)
	}
	m := regexp.MustCompile(`<a href="/admin/audit\?before=(\d+)">Older entries</a>`).FindStringSubmatch(first)
	if m == nil {
		t.Fatalf("no Older entries link:\n%s", first)
	}
	second := e.do(req{method: "GET", path: "/admin/audit?before=" + m[1], cookie: admin}).Body.String()
	if n := strings.Count(second, "<tr><td><time"); n != total-auditPageSize || !strings.Contains(second, "<td>entry 0</td>") ||
		strings.Contains(second, "Older entries</a>") || !strings.Contains(second, `<a href="/admin/audit">Newest entries</a>`) {
		t.Errorf("second page: %d rows:\n%s", n, second)
	}
	// The pages do not overlap: entries 0-4 are only on the second.
	if strings.Contains(first, "<td>entry 4</td>") || !strings.Contains(first, "<td>entry 5</td>") ||
		!strings.Contains(second, "<td>entry 4</td>") || strings.Contains(second, "<td>entry 5</td>") {
		t.Error("pages overlap or miss an entry")
	}
	for _, bad := range []string{"x", "0", "-1"} {
		if rec := e.do(req{method: "GET", path: "/admin/audit?before=" + bad, cookie: admin}); rec.Code != http.StatusBadRequest {
			t.Errorf("before=%s = %d", bad, rec.Code)
		}
	}
	if b := e.do(req{method: "GET", path: "/admin/audit?before=999999", cookie: admin}).Body.String(); !strings.Contains(b, "There are no older entries.") {
		t.Errorf("unknown cursor page:\n%s", b)
	}
}
