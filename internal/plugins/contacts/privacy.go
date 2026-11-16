package contacts

import (
	"context"

	"go.privatebychoice.com/shellshawk/internal/events"
	"go.privatebychoice.com/shellshawk/internal/export"
)

// export returns the member's contacts and contact groups.
func (p *Plugin) export(ctx context.Context, user int64) ([]export.File, error) {
	list, err := p.List(ctx, user)
	if err != nil {
		return nil, err
	}
	type contactOut struct {
		Username string `json:"username"`
		Note     string `json:"note"`
		Friend   bool   `json:"friend"`
		Added    any    `json:"added"`
	}
	var cs []contactOut
	for _, c := range list {
		cs = append(cs, contactOut{c.Username, c.Note, c.Mutual, c.AddedAt})
	}
	groups, err := p.Groups(ctx, user)
	if err != nil {
		return nil, err
	}
	gs := map[string][]string{}
	for _, g := range groups {
		members, err := p.GroupMembers(ctx, user, g.ID)
		if err != nil {
			return nil, err
		}
		names := []string{}
		for _, m := range members {
			names = append(names, m.Username)
		}
		gs[g.Name] = names
	}
	f, err := export.JSON("contacts.json", map[string]any{"contacts": cs, "groups": gs})
	return []export.File{f}, err
}

// erase removes the member's contact list and groups, and removes them from
// everyone else's contacts and groups.
func (p *Plugin) erase(ctx context.Context, e events.Event) error {
	if _, err := p.h.DB.ExecContext(ctx, `DELETE FROM contacts_groups WHERE owner_id = ?`, e.UserID); err != nil {
		return err
	}
	_, err := p.h.DB.ExecContext(ctx, `DELETE FROM contacts_entries WHERE owner_id = ? OR contact_id = ?`, e.UserID, e.UserID)
	return err
}
