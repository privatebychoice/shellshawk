package sessions

import (
	"strconv"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/sshd"
)

// Who names the connection's account for staff.
func (c Connection) Who() string {
	switch {
	case c.UserID == 0:
		return "Someone registering with an invite"
	case c.Username == "":
		return "Deleted account"
	}
	return c.Username
}

// Uses says what the connection is doing: its login mode when that limits
// it, and the terminal and file transfer sessions it has open.
func (c Connection) Uses() string {
	var uses []string
	switch sshd.Mode(c.Mode) {
	case sshd.ModePending:
		uses = append(uses, "awaiting approval")
	case sshd.ModeAddKey:
		uses = append(uses, "adding a key")
	}
	if c.Terminals > 0 {
		uses = append(uses, plural(c.Terminals, "terminal", "terminals"))
	}
	if c.Transfers > 0 {
		uses = append(uses, plural(c.Transfers, "file transfer", "file transfers"))
	}
	if len(uses) == 0 {
		return "connecting"
	}
	return strings.Join(uses, " and ")
}

// Idle says how long the member has sent nothing, in whole minutes.
func (c Connection) Idle(now time.Time) string {
	if m := int(now.Sub(c.LastActive) / time.Minute); m >= 1 {
		return plural(m, "minute", "minutes")
	}
	return "under a minute"
}

// Describe is a one-line summary: "alice: 1 terminal, idle 3 minutes".
func (c Connection) Describe(now time.Time) string {
	return c.Who() + ": " + c.Uses() + ", idle " + c.Idle(now)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}
