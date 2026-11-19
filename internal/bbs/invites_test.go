package bbs

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"go.privatebychoice.com/shellshawk/internal/auth"
)

func TestInviteState(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)
	tests := []struct {
		name string
		inv  auth.Invite
		want string
	}{
		{"usable", auth.Invite{MaxUses: 2, Uses: 1, ExpiresAt: &future}, "usable"},
		{"no expiry", auth.Invite{MaxUses: 1}, "usable"},
		{"used up", auth.Invite{MaxUses: 1, Uses: 1, ExpiresAt: &future}, "used up"},
		{"expired", auth.Invite{MaxUses: 1, ExpiresAt: &past}, "expired"},
		{"expires now", auth.Invite{MaxUses: 1, ExpiresAt: &now}, "expired"},
		{"revoked wins", auth.Invite{MaxUses: 1, Uses: 1, ExpiresAt: &past, RevokedAt: &past}, "revoked"},
	}
	for _, tt := range tests {
		if got := inviteState(tt.inv, now); got != tt.want {
			t.Errorf("%s: %q, want %q", tt.name, got, tt.want)
		}
	}
}

func TestInviteLabel(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	future := now.Add(time.Hour)
	tests := []struct {
		inv  auth.Invite
		want string
	}{
		{auth.Invite{ID: 4, MaxUses: 5, Uses: 2, ExpiresAt: &future, Note: "for the book club"}, "Invite 4: usable, 3 of 5 uses left, note: for the book club"},
		{auth.Invite{ID: 5, MaxUses: 1}, "Invite 5: usable, 1 of 1 uses left"},
		{auth.Invite{ID: 6, MaxUses: 1, Uses: 1, Note: "sam"}, "Invite 6: used up, note: sam"},
		{auth.Invite{ID: 7, MaxUses: 3, RevokedAt: &now}, "Invite 7: revoked"},
	}
	for _, tt := range tests {
		if got := inviteLabel(tt.inv, now); got != tt.want {
			t.Errorf("inviteLabel = %q, want %q", got, tt.want)
		}
	}
}

func TestInviteListAndRevoke(t *testing.T) {
	e := startBBS(t)
	signer := e.accessibleAdmin(t, "ruth")
	ctx := context.Background()
	u, _ := e.auth.UserByUsername(ctx, "ruth")
	if _, _, err := e.auth.CreateInvite(ctx, u.ID, auth.InviteOptions{MaxUses: 2, TTL: 24 * time.Hour, Note: "keep"}); err != nil {
		t.Fatal(err)
	}
	_, gone, err := e.auth.CreateInvite(ctx, u.ID, auth.InviteOptions{TTL: 24 * time.Hour, RequireApproval: true, Note: "revoke me"})
	if err != nil {
		t.Fatal(err)
	}

	// 6 Administration, 6 View or revoke invites. Newest first: 1 = "revoke
	// me", 2 = "keep", 3 = the used-up bootstrap invite. 3 shows its
	// details, Enter. 1 opens "revoke me": 1 Revoke, 1 No: back to the
	// list. 1, 1 Revoke, 2 Yes, Enter dismisses "Invite revoked."; the
	// list now shows it revoked. Then q until logged out.
	input := strings.Join([]string{"6", "6", "3", "", "1", "1", "1", "1", "1", "2", "", "q", "q", "q"}, "\r") + "\r"
	out := e.session(t, "ruth", ssh.PublicKeys(signer), input)
	id := strconv.FormatInt(gone.ID, 10)
	for _, want := range []string{
		"3 invite(s), 2 usable. Choose one to see its details or revoke it.",
		"Invite " + id + ": usable, 1 of 1 uses left, note: revoke me",
		"usable, 2 of 2 uses left, note: keep",
		": used up, note: bootstrap administrator",
		"Uses: 1 of 1 used, 0 left.",
		"This invite can no longer be used, so there is nothing to revoke.",
		"State: usable. Uses: 0 of 1 used, 1 left.",
		"New accounts need approval: yes. Note: revoke me",
		"Revoke invite " + id + "? It can no longer be used.",
		"Invite revoked.",
		"3 invite(s), 1 usable.",
		"Invite " + id + ": revoked, note: revoke me",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
	if n := strings.Count(out, "Revoke invite "+id+"?"); n != 2 {
		t.Errorf("confirmation asked %d times, want 2", n)
	}
	invs, _ := e.auth.Invites(ctx, u.ID)
	for _, inv := range invs {
		if revoked := inv.RevokedAt != nil; revoked != (inv.ID == gone.ID) {
			t.Errorf("invite %d revoked = %v", inv.ID, revoked)
		}
	}
	if t.Failed() {
		t.Logf("output:\n%s", out)
	}
}
