package messages

import (
	"context"
	"errors"
	"strconv"

	"go.privatebychoice.com/shellshawk/internal/notify"
	"go.privatebychoice.com/shellshawk/internal/plugin"
	"go.privatebychoice.com/shellshawk/internal/tui"
)

// NotifyNew is the notification kind sent to each recipient of a message.
const NotifyNew = "messages:new"

func (p *Plugin) notificationKinds() []plugin.NotificationKind {
	return []plugin.NotificationKind{{Key: "new", Label: "New private messages", Help: "Someone sent you a private message.",
		Default: true, OpenLabel: "Read the message", Open: p.openNotification,
		WebPath: notify.RefPath("/m/")}}
}

// notifyRecipients tells each recipient but the sender about message id.
// A failure is logged: the message has been delivered either way.
func (p *Plugin) notifyRecipients(ctx context.Context, from, id int64, subject string, to []int64) {
	if p.h.Notify == nil {
		return
	}
	for _, uid := range to {
		if uid == from {
			continue
		}
		if _, _, err := p.h.Notify.Add(ctx, notify.New{UserID: uid, Kind: NotifyNew, ActorID: from, Text: subject,
			Ref: strconv.FormatInt(id, 10)}); err != nil {
			p.h.Log.Error("message notification failed", "message_id", id, "user_id", uid, "err", err)
		}
	}
}

// openNotification shows the message, as from the inbox.
func (p *Plugin) openNotification(ctx context.Context, s plugin.Session, n notify.Notification) error {
	id, _ := strconv.ParseInt(n.Ref, 10, 64)
	err := p.view(ctx, s, id, Inbox)
	if errors.Is(err, ErrNotFound) {
		return tui.Message(ctx, s.UI(), s.Title("Message"), "That message is no longer in your inbox.")
	}
	return err
}
