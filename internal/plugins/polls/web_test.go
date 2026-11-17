package polls

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
)

func TestWebListAndPoll(t *testing.T) {
	p, e := setup(t)
	alice, bob := e.User("alice"), e.User("bob")
	open, _ := p.Create(e.Ctx, Spec{Question: "Lunch <today>?", Options: []string{"Pizza & co", "Soup"}, CreatorID: alice})
	pinned, _ := p.Create(e.Ctx, Spec{Question: "Rules?", Options: []string{"Yes", "No"}, Pinned: true, CreatorID: e.Admin})
	closed, _ := p.Create(e.Ctx, Spec{Question: "Old one", Options: []string{"A", "B"}, CreatorID: alice})
	if err := p.Close(e.Ctx, alice, closed); err != nil {
		t.Fatal(err)
	}
	attached, _ := p.Create(e.Ctx, Spec{Question: "In a post", Options: []string{"A", "B"}, Context: "conferences:post:1", CreatorID: alice})
	id := func(n int64) map[string]string { return map[string]string{"id": strconv.FormatInt(n, 10)} }

	list, err := e.WebGet(p, "/", nil, bob)
	b := string(list.Body)
	if err != nil || !strings.Contains(b, "Pinned: <a href=\"/p/polls/"+strconv.FormatInt(pinned, 10)) ||
		!strings.Contains(b, "Lunch &lt;today&gt;?") || strings.Contains(b, "Old one") || strings.Contains(b, "In a post") ||
		strings.Index(b, "Rules?") > strings.Index(b, "Lunch") {
		t.Errorf("open list = %s, %v", b, err)
	}
	if cl, err := e.WebGet(p, "/closed", nil, bob); err != nil || cl.Title != "Closed polls" || !strings.Contains(string(cl.Body), "Old one") {
		t.Errorf("closed list = %s, %v", cl.Body, err)
	}

	tests := []struct {
		name     string
		poll     int64
		want     []string
		notWant  []string
		notFound bool
	}{
		{"open, not voted", open, []string{
			`<legend>Your vote: choose one</legend>`, `type="radio" name="option"`, " required>", "Pizza &amp; co",
			`<button type="submit">Vote</button>`, "Results are shown after you vote or when the poll closes.",
			`action="/p/polls/` + strconv.FormatInt(open, 10) + `/vote"`, `name="csrf"`,
		}, []string{"<h2", "percent"}, false},
		{"closed: results, no form", closed, []string{"This poll is closed.", "<h2 id=", ">Results</h2>", "0 vote(s) from 0 member(s)."},
			[]string{"<form"}, false},
		{"attached poll is not on the Polls pages", attached, nil, nil, true},
		{"unknown poll", 9999, nil, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := e.WebGet(p, "/{id}", id(tt.poll), bob)
			if tt.notFound {
				if !errors.Is(err, plugin.ErrWebNotFound) {
					t.Errorf("err = %v, want not found", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tt.want {
				if !strings.Contains(string(page.Body), w) {
					t.Errorf("missing %q in:\n%s", w, page.Body)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(string(page.Body), w) {
					t.Errorf("unexpected %q in:\n%s", w, page.Body)
				}
			}
		})
	}
	if _, err := e.WebPost(p, "/{id}/vote", id(attached), url.Values{"option": {"1"}}, bob); !errors.Is(err, plugin.ErrWebNotFound) {
		t.Errorf("vote in attached poll from the Polls pages: err = %v, want not found", err)
	}
}

func TestWebVote(t *testing.T) {
	p, e := setup(t)
	alice, bob := e.User("alice"), e.User("bob")
	single, _ := p.Create(e.Ctx, Spec{Question: "One?", Options: []string{"A", "B"}, CreatorID: alice})
	multi, _ := p.Create(e.Ctx, Spec{Question: "Many?", Options: []string{"X", "Y", "Z"}, Multi: true, Named: true, CreatorID: alice})
	sp, _ := p.Get(e.Ctx, bob, single)
	mp, _ := p.Get(e.Ctx, bob, multi)
	opt := func(o Option) string { return strconv.FormatInt(o.ID, 10) }
	id := func(n int64) map[string]string { return map[string]string{"id": strconv.FormatInt(n, 10)} }

	tests := []struct {
		name   string
		poll   int64
		form   url.Values
		status int // 0 = accepted
	}{
		{"no choice", single, url.Values{}, http.StatusBadRequest},
		{"two choices in a single poll", single, url.Values{"option": {opt(sp.Options[0]), opt(sp.Options[1])}}, http.StatusBadRequest},
		{"option of another poll", single, url.Values{"option": {opt(mp.Options[0])}}, http.StatusBadRequest},
		{"not a number", single, url.Values{"option": {"x"}}, http.StatusBadRequest},
		{"single choice", single, url.Values{"option": {opt(sp.Options[1])}}, 0},
		{"change it", single, url.Values{"option": {opt(sp.Options[0])}}, 0},
		{"several in a multi poll", multi, url.Values{"option": {opt(mp.Options[0]), opt(mp.Options[2])}}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			page, err := e.WebPost(p, "/{id}/vote", id(tt.poll), tt.form, bob)
			var we *plugin.WebError
			switch {
			case tt.status == 0 && (err != nil || page.Redirect != "/p/polls/"+strconv.FormatInt(tt.poll, 10)):
				t.Errorf("vote = %+v, %v", page, err)
			case tt.status != 0 && (!errors.As(err, &we) || we.Status != tt.status):
				t.Errorf("err = %v, want status %d", err, tt.status)
			}
		})
	}

	// After voting: the choice is checked, the button changes and the
	// results show, with names on a named poll.
	page, _ := e.WebGet(p, "/{id}", id(single), bob)
	b := string(page.Body)
	if !strings.Contains(b, `value="`+opt(sp.Options[0])+`" checked`) || !strings.Contains(b, "Change your vote") ||
		!strings.Contains(b, "Option 1, A: 1 vote(s), 100 percent (your vote).") || !strings.Contains(b, `<meter min="0" max="100" value="100" aria-hidden="true">`) ||
		!strings.Contains(b, "You have voted.") {
		t.Errorf("after voting:\n%s", b)
	}
	page, _ = e.WebGet(p, "/{id}", id(multi), alice) // the creator sees results without voting
	if b := string(page.Body); !strings.Contains(b, `type="checkbox"`) || strings.Contains(b, " required>") ||
		!strings.Contains(b, "Voted: bob") || !strings.Contains(b, "everyone will see your choice") {
		t.Errorf("multi poll for its creator:\n%s", b)
	}

	// Closed: no more votes.
	p.Close(e.Ctx, alice, single)
	var we *plugin.WebError
	if _, err := e.WebPost(p, "/{id}/vote", id(single), url.Values{"option": {opt(sp.Options[1])}}, bob); !errors.As(err, &we) || we.Status != http.StatusBadRequest {
		t.Errorf("vote in closed poll: err = %v", err)
	}

	// Without polls.vote: no form, and a posted vote is refused.
	member, err := e.Perms.GroupByName(e.Ctx, perm.GroupMember)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Perms.Revoke(e.Ctx, e.Admin, member.ID, PermVote); err != nil {
		t.Fatal(err)
	}
	page, _ = e.WebGet(p, "/{id}", id(multi), bob)
	if b := string(page.Body); strings.Contains(b, "<form") || !strings.Contains(b, "You cannot vote in polls.") {
		t.Errorf("member without polls.vote:\n%s", b)
	}
	if _, err := e.WebPost(p, "/{id}/vote", id(multi), url.Values{"option": {opt(mp.Options[1])}}, bob); !errors.As(err, &we) || we.Status != http.StatusForbidden {
		t.Errorf("vote without polls.vote: err = %v", err)
	}
}
