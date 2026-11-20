package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestClientAddr(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8:ff::/48")}
	tests := []struct {
		name    string
		proxies []netip.Prefix
		remote  string
		xff     []string // X-Forwarded-For header lines
		want    string   // "" = no address
	}{
		{"direct", nil, "198.51.100.7:4000", nil, "198.51.100.7"},
		{"header ignored without trusted proxies", nil, "198.51.100.7:4000", []string{"203.0.113.9"}, "198.51.100.7"},
		{"header ignored from an untrusted address", trusted, "198.51.100.7:4000", []string{"203.0.113.9"}, "198.51.100.7"},
		{"from a trusted proxy", trusted, "10.0.0.2:4000", []string{"203.0.113.9"}, "203.0.113.9"},
		{"client-supplied entries are skipped", trusted, "10.0.0.2:4000", []string{"1.2.3.4, 5.6.7.8, 203.0.113.9"}, "203.0.113.9"},
		{"two trusted proxies", trusted, "10.0.0.2:4000", []string{"203.0.113.9, 10.9.9.9"}, "203.0.113.9"},
		{"header split over lines", trusted, "10.0.0.2:4000", []string{"1.2.3.4", "203.0.113.9, 10.9.9.9"}, "203.0.113.9"},
		{"only trusted hops", trusted, "10.0.0.2:4000", []string{"10.3.3.3"}, "10.3.3.3"},
		{"no header from a trusted proxy", trusted, "10.0.0.2:4000", nil, "10.0.0.2"},
		{"nonsense from a trusted proxy", trusted, "10.0.0.2:4000", []string{"203.0.113.9, not-an-ip"}, "10.0.0.2"},
		{"IPv6 proxy and client", trusted, "[2001:db8:ff::1]:443", []string{"2001:db8:1::5"}, "2001:db8:1::5"},
		{"mapped client", trusted, "10.0.0.2:4000", []string{"::ffff:203.0.113.9"}, "203.0.113.9"},
		{"unreadable remote", nil, "pipe", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{cfg: Config{TrustedProxies: tt.proxies}}
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tt.remote
			for _, h := range tt.xff {
				r.Header.Add("X-Forwarded-For", h)
			}
			got, ok := s.clientAddr(r)
			if (tt.want == "") != !ok || (ok && got.String() != tt.want) {
				t.Errorf("clientAddr = %v, %v; want %q", got, ok, tt.want)
			}
		})
	}
}

// TestLoginLimitBehindProxy: behind a trusted proxy each client has its
// own failure count, so one client's bad codes do not lock out everyone;
// and a successful login does not clear the client's count.
func TestLoginLimitBehindProxy(t *testing.T) {
	e := setup(t, false)
	e.srv.cfg.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}
	try := func(client, user, code string) int {
		t.Helper()
		return e.do(req{method: "POST", path: "/login", origin: origin, remote: "10.0.0.1:5000",
			headers: map[string]string{"X-Forwarded-For": client}, form: url.Values{"username": {user}, "code": {code}}}).Code
	}
	code := func(user int64) string {
		t.Helper()
		c, _, err := e.sessions.NewCode(context.Background(), user)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	for i := range loginIPFailures {
		try("203.0.113.66", "nobody"+string(rune('a'+i)), "AAAA-AAAA")
	}
	if got := try("203.0.113.66", "alice", code(e.alice)); got != http.StatusTooManyRequests {
		t.Errorf("the guessing client = %d, want 429", got)
	}
	if got := try("198.51.100.20", "alice", code(e.alice)); got != http.StatusSeeOther {
		t.Errorf("another client behind the same proxy = %d, want 303", got)
	}

	// A login in between does not clear the client's count.
	for i := range loginIPFailures - 1 {
		try("198.51.100.30", "nobody"+string(rune('a'+i)), "AAAA-AAAA")
	}
	if got := try("198.51.100.30", "alice", code(e.alice)); got != http.StatusSeeOther {
		t.Fatalf("login under the limit = %d", got)
	}
	try("198.51.100.30", "nobodyz", "AAAA-AAAA")
	if got := try("198.51.100.30", "alice", code(e.alice)); got != http.StatusTooManyRequests {
		t.Errorf("after the limit = %d, want 429 (the login reset the count)", got)
	}
}

// TestWebLoginBlocksAudited: the web login writes one audit row when an
// account or an address reaches its failure limit, and no address.
func TestWebLoginBlocksAudited(t *testing.T) {
	e := setup(t, false)
	try := func(remote, user string) {
		e.do(req{method: "POST", path: "/login", origin: origin, remote: remote, form: url.Values{"username": {user}, "code": {"AAAA-AAAA"}}})
	}
	for i := range 2 * loginUserFailures {
		try("192.0.2."+strconv.Itoa(10+i)+":1000", "alice")
	}
	for i := range 2 * loginIPFailures {
		try("198.51.100.9:1000", "ghost"+strconv.Itoa(i))
	}
	rows, err := e.srv.cfg.Auth.DB().QueryContext(context.Background(), `SELECT target_type || ':' || target_id || ':' || detail FROM audit_log WHERE action = 'login.blocked' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var s string
		rows.Scan(&s)
		got = append(got, s)
	}
	want := []string{"user:" + strconv.FormatInt(e.alice, 10) + ":web code", "address::web code"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("audit rows = %q, want %q", got, want)
	}
}
