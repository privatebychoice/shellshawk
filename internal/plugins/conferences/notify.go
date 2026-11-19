package conferences

import (
	"context"
	"errors"
	"strconv"

	"go.privatebychoice.com/shellshawk/internal/notify"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// NotifyReply is the notification kind sent to a thread's author when
// someone else replies.
const NotifyReply = "conferences:reply"

func (p *Plugin) notificationKinds() []plugin.NotificationKind {
	return []plugin.NotificationKind{{Key: "reply", Label: "Replies to your threads", Help: "Someone replied to a thread you started.",
		Default: true, OpenLabel: "Read the thread", Open: p.openNotification}}
}

// notifyAuthor tells t's author that user replied, if the author can still
// read the thread. A failure is logged: the reply has been posted either
// way.
func (p *Plugin) notifyAuthor(ctx context.Context, user int64, t Thread) {
	if p.h.Notify == nil || t.AuthorID == 0 || t.AuthorID == user {
		return
	}
	if _, _, _, err := p.Thread(ctx, t.AuthorID, t.ID); err != nil {
		if !errors.Is(err, ErrNotFound) {
			p.h.Log.Error("reply notification: check access", "thread_id", t.ID, "err", err)
		}
		return
	}
	if _, _, err := p.h.Notify.Add(ctx, notify.New{UserID: t.AuthorID, Kind: NotifyReply, ActorID: user, Text: t.Title,
		Ref: strconv.FormatInt(t.ID, 10)}); err != nil {
		p.h.Log.Error("reply notification failed", "thread_id", t.ID, "err", err)
	}
}

// openNotification shows the thread.
func (p *Plugin) openNotification(ctx context.Context, s plugin.Session, n notify.Notification) error {
	id, _ := strconv.ParseInt(n.Ref, 10, 64)
	err := p.thread(ctx, s, id)
	if errors.Is(err, ErrNotFound) {
		return tui.Message(ctx, s.UI(), s.Title("Conferences"), "That thread no longer exists, or you can no longer read it.")
	}
	return err
}
