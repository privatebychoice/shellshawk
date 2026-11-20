package chat

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.privatebychoice.com/shellshawk/internal/auth"
	"go.privatebychoice.com/shellshawk/internal/form"
	"go.privatebychoice.com/shellshawk/internal/notify"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/privacy"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// PermPage lets a member page others: ask them to come and talk in a chat.
const PermPage = "chat.page"

// NotifyPage is the notification kind a page sends.
const NotifyPage = "chat:page"

// setPageMinutes is the plugin setting: minutes before a member may page
// the same person again.
const (
	setPageMinutes     = "page_minutes"
	defaultPageMinutes = 5
	// talkPrefix starts the names of the private chats paging creates.
	talkPrefix = "talk-"
)

// ErrCannotPage is returned when the member asked for cannot be paged:
// offline, not accepting pages from the sender, or pages turned off. The
// reasons are not told apart, so a page reveals no more than the
// member's own privacy choices allow.
var ErrCannotPage = errors.New("cannot be paged right now")

// pager remembers when each member last paged each other member (in
// memory: a restart forgets it).
type pager struct {
	mu   sync.Mutex
	last map[[2]int64]time.Time
}

// wait returns how long from must wait before paging to again, or 0 and
// records the page.
func (pg *pager) wait(from, to int64, now time.Time, every time.Duration) time.Duration {
	pg.mu.Lock()
	defer pg.mu.Unlock()
	if pg.last == nil {
		pg.last = map[[2]int64]time.Time{}
	}
	for k, t := range pg.last {
		if now.Sub(t) >= every {
			delete(pg.last, k)
		}
	}
	key := [2]int64{from, to}
	if t, ok := pg.last[key]; ok {
		return every - now.Sub(t)
	}
	pg.last[key] = now
	return 0
}

func (p *Plugin) pageEvery(ctx context.Context) time.Duration {
	v, err := p.h.Settings.Get(ctx, setPageMinutes)
	n, cerr := strconv.Atoi(v)
	if err != nil || cerr != nil {
		return defaultPageMinutes * time.Minute
	}
	return time.Duration(n) * time.Minute
}

// pageSetting is the administrator's setting for how often a member may
// page the same person.
func pageSetting() plugin.Setting {
	return plugin.Setting{Field: form.Field{Name: setPageMinutes, Label: "Minutes before a member can page the same person again",
		Kind: form.SingleLine, Subtype: form.Int, Required: true, Min: form.Bound(1), Max: form.Bound(1440)},
		Default: strconv.Itoa(defaultPageMinutes)}
}

func (p *Plugin) notificationKinds() []plugin.NotificationKind {
	return []plugin.NotificationKind{{Key: "page", Label: "Pages", Help: "Someone would like to talk to you in a chat. Turning this off also stops people paging you.",
		Default: true, OpenLabel: "Go to the chat", Open: p.openPage, WebPath: notify.RefPath("/c/")}}
}

// pageable reports whether from may page to now: to accepts pages from
// from (privacy setting "Who can page you"), lets from see that they are
// online ("That you are online now"), is online (over SSH, or in a chat on
// the web) and has page notifications on. Every refusal looks the same to
// from, and the privacy settings are checked before presence, so paging
// never reveals that someone is online to a member who may not see it.
func (p *Plugin) pageable(ctx context.Context, from, to int64) (bool, error) {
	if p.h.Privacy != nil {
		for _, f := range []privacy.Field{privacy.Pages, privacy.Online} {
			if ok, err := p.h.Privacy.Allows(ctx, from, to, f); err != nil || !ok {
				return false, err
			}
		}
	}
	online := p.h.Presence != nil && p.h.Presence.IsOnline(to)
	if !online && !p.hub.present(to) {
		return false, nil
	}
	return p.h.Notify.Enabled(ctx, to, NotifyPage)
}

// Page asks targetName to come and talk to from in channel c, which from
// must be able to enter. A private chat invites the member if needed; in
// any other channel they must already be allowed in. The member gets a
// notification, and a line straight away if they are in a chat.
func (p *Plugin) Page(ctx context.Context, from auth.User, targetName string, c Channel) (auth.User, error) {
	if p.h.Notify == nil {
		return auth.User{}, fmt.Errorf("%w: paging is not available", ErrInvalid)
	}
	if err := p.h.Perms.Require(ctx, from.ID, PermPage); err != nil {
		return auth.User{}, err
	}
	if ok, err := p.CanAccess(ctx, from.ID, c); err != nil || !ok {
		return auth.User{}, errors.Join(perm.ErrForbidden, err)
	}
	to, err := p.member(ctx, targetName)
	if err != nil || to.Status != auth.StatusActive {
		return auth.User{}, fmt.Errorf("%w: no active member called %q", ErrInvalid, strings.TrimPrefix(strings.TrimSpace(targetName), "@"))
	}
	if to.ID == from.ID {
		return auth.User{}, fmt.Errorf("%w: you cannot page yourself", ErrInvalid)
	}
	if ok, err := p.pageable(ctx, from.ID, to.ID); err != nil || !ok {
		return to, errors.Join(ErrCannotPage, err)
	}
	if c.Kind == KindAdHoc {
		if err := p.Invite(ctx, from.ID, c, to.ID); err != nil {
			return to, err
		}
	}
	if ok, err := p.CanAccess(ctx, to.ID, c); err != nil || !ok {
		if err != nil {
			return to, err
		}
		return to, fmt.Errorf("%w: %s cannot join #%s; page them from a private chat instead", ErrInvalid, to.Username, c.Name)
	}
	every := p.pageEvery(ctx)
	if left := p.pages.wait(from.ID, to.ID, p.now(), every); left > 0 {
		mins := int((left + time.Minute - 1) / time.Minute)
		return to, fmt.Errorf("%w: you paged %s recently; you can page them again in %d minute(s)", ErrInvalid, to.Username, mins)
	}
	id, added, err := p.h.Notify.Add(ctx, notify.New{UserID: to.ID, Kind: NotifyPage, ActorID: from.ID,
		Text: "would like to talk in #" + c.Name, Ref: strconv.FormatInt(c.ID, 10)})
	if err != nil {
		return to, err
	}
	if !added { // turned off between the check and now
		return to, ErrCannotPage
	}
	live := eventLine(p.now(), fmt.Sprintf("%s is paging you to talk in #%s. Type /join %s to go there.", from.Username, c.Name, c.Name))
	liveWeb := eventLine(p.now(), fmt.Sprintf("%s is paging you to talk in #%s. Open it from Notifications or the chat list.", from.Username, c.Name))
	if p.hub.tell(to.ID, live, liveWeb) {
		if err := p.h.Notify.MarkSeen(ctx, to.ID, id); err != nil {
			p.h.Log.Error("mark page seen", "err", err)
		}
	}
	p.h.Log.Info("member paged", "from", from.ID, "to", to.ID, "channel_id", c.ID)
	return to, nil
}

// pageMessage describes a page failure for the member who paged.
func pageMessage(name string, err error) string {
	if errors.Is(err, ErrCannotPage) {
		return name + " cannot be paged right now."
	}
	if errors.Is(err, ErrInvalid) {
		return sentence(err)
	}
	return errorMessage(err)
}

// talkChat returns the private chat for paging between a and b: one of
// them created it and the other is its only invitee. If there is none,
// a creates one named talk-<a>-<b>.
func (p *Plugin) talkChat(ctx context.Context, a, b auth.User) (Channel, error) {
	var id int64
	err := p.h.DB.QueryRowContext(ctx, `SELECT c.id FROM chat_channels c
		WHERE c.kind = 'adhoc' AND c.name LIKE ? ESCAPE '\' AND
			((c.creator_id = ? AND EXISTS (SELECT 1 FROM chat_invites i WHERE i.channel_id = c.id AND i.user_id = ?)) OR
			 (c.creator_id = ? AND EXISTS (SELECT 1 FROM chat_invites i WHERE i.channel_id = c.id AND i.user_id = ?)))
			AND (SELECT count(*) FROM chat_invites i WHERE i.channel_id = c.id) = 1
		ORDER BY c.id LIMIT 1`, talkPrefix+"%", a.ID, b.ID, b.ID, a.ID).Scan(&id)
	switch {
	case err == nil:
		return p.Get(ctx, id)
	case !errors.Is(err, sql.ErrNoRows):
		return Channel{}, fmt.Errorf("chat: find talk chat: %w", err)
	}
	base := talkName(a.Username, b.Username)
	for i := 1; i <= 9; i++ {
		name := base
		if i > 1 {
			name = base + "-" + strconv.Itoa(i)
		}
		id, err = p.Create(ctx, a.ID, NewChannel{Name: name, Kind: KindAdHoc, Topic: a.Username + " and " + b.Username, RetentionDays: DefaultRetention})
		if errors.Is(err, ErrExists) {
			continue
		}
		if err != nil {
			return Channel{}, err
		}
		return p.Get(ctx, id)
	}
	return Channel{}, ErrExists
}

// talkName builds a channel name from two usernames: lowercase letters,
// digits and hyphens, at most 29 characters so a "-N" suffix still fits.
func talkName(a, b string) string {
	slug := func(s string) string {
		var sb strings.Builder
		for _, r := range strings.ToLower(s) {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				sb.WriteRune(r)
			} else {
				sb.WriteByte('-')
			}
		}
		return strings.Trim(sb.String(), "-")
	}
	name := talkPrefix + slug(a) + "-" + slug(b)
	if len(name) > 29 {
		name = name[:29]
	}
	return strings.TrimRight(name, "-")
}

// pageToTalk pages targetName into the private talk chat between from and
// them, creating it if needed. Nothing is created for a member who cannot
// be paged. Errors for the member are ErrInvalid, ErrCannotPage and
// perm.ErrForbidden.
func (p *Plugin) pageToTalk(ctx context.Context, from auth.User, targetName string) (auth.User, Channel, error) {
	if err := p.h.Perms.Require(ctx, from.ID, PermCreate); err != nil {
		return auth.User{}, Channel{}, err
	}
	to, err := p.member(ctx, targetName)
	if err != nil {
		return auth.User{}, Channel{}, err
	}
	if to.ID == from.ID {
		return to, Channel{}, fmt.Errorf("%w: you cannot page yourself", ErrInvalid)
	}
	if ok, err := p.pageable(ctx, from.ID, to.ID); err != nil || !ok {
		return to, Channel{}, errors.Join(ErrCannotPage, err)
	}
	c, err := p.talkChat(ctx, from, to)
	if err != nil {
		return to, c, err
	}
	_, err = p.Page(ctx, from, to.Username, c)
	return to, c, err
}

// pageForm asks who to page, pages them into a private talk chat and
// enters it.
func (p *Plugin) pageForm(ctx context.Context, s plugin.Session) error {
	u, err := p.h.Auth.UserByID(ctx, s.UserID())
	if err != nil {
		return err
	}
	fm := &form.Form{Title: "Page someone", Intro: "Ask a member to come and talk to you in a private chat. They see it the next time they move between screens, or straight away if they are in a chat.",
		Fields: []form.Field{{Name: "user", Label: "Username", Kind: form.SingleLine, Required: true, MaxLen: 64}}}
	vals, errs := form.Values{}, form.Errors{}
	for {
		v, err := s.Form(ctx, fm, vals, errs)
		if err != nil {
			return err
		}
		vals = v
		to, c, err := p.pageToTalk(ctx, u, v["user"])
		if err == nil {
			s.Log().Info("paged from the chat menu", "to", to.ID, "channel_id", c.ID)
			if err := tui.Message(ctx, s.UI(), s.Title("Page someone"),
				fmt.Sprintf("%s has been paged. Wait for them in #%s.", to.Username, c.Name)); err != nil {
				return err
			}
			return p.Enter(ctx, s, c.ID)
		}
		if errors.Is(err, perm.ErrForbidden) || (!errors.Is(err, ErrInvalid) && !errors.Is(err, ErrCannotPage)) {
			return err
		}
		errs = form.Errors{"user": errors.New(strings.TrimSuffix(pageMessage(strings.TrimSpace(v["user"]), err), "."))}
	}
}

// openPage takes the member to the chat they were paged to.
func (p *Plugin) openPage(ctx context.Context, s plugin.Session, n notify.Notification) error {
	id, _ := strconv.ParseInt(n.Ref, 10, 64)
	c, err := p.Get(ctx, id)
	ok := false
	if err == nil {
		ok, err = p.CanAccess(ctx, s.UserID(), c)
	}
	if errors.Is(err, ErrNotFound) || (err == nil && !ok) {
		return tui.Message(ctx, s.UI(), s.Title("Chat"), "That chat no longer exists, or you can no longer join it.")
	}
	if err != nil {
		return err
	}
	return p.Enter(ctx, s, id)
}
