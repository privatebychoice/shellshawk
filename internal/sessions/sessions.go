// Package sessions lets staff see who is connected over SSH and end a
// connection. The connections themselves are recorded by presence.Conns;
// this package adds the permission checks, usernames and audit records.
package sessions

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/perm"
	"go.privatebychoice.com/shellshawk/internal/presence"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// ErrNotFound is returned when a connection is no longer open.
var ErrNotFound = errors.New("sessions: connection not found")

// EndedMessage is what a member sees when staff end their connection.
const EndedMessage = "Your connection was ended by an administrator or moderator."

// Connection is an open connection with the account's name.
type Connection struct {
	presence.ConnInfo
	Username string // "" while someone registers with an invite
}

// Service lists and ends connections.
type Service struct {
	db    *sql.DB
	conns *presence.Conns
	now   func() time.Time
	log   *slog.Logger
}

// NewService returns a Service. now may be nil.
func NewService(db *sql.DB, conns *presence.Conns, now func() time.Time, log *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, conns: conns, now: now, log: log.With("component", "sessions")}
}

// List returns every open connection, oldest first. It requires
// core.sessions.manage.
func (s *Service) List(ctx context.Context, actor int64) ([]Connection, error) {
	if err := perm.RequireTx(ctx, s.db, actor, perm.SessionsManage); err != nil {
		return nil, err
	}
	names := map[int64]string{}
	var out []Connection
	for _, c := range s.conns.List() {
		if c.UserID != 0 {
			if _, ok := names[c.UserID]; !ok {
				var n string
				err := s.db.QueryRowContext(ctx, `SELECT username FROM users WHERE id = ?`, c.UserID).Scan(&n)
				if err != nil && !errors.Is(err, sql.ErrNoRows) {
					return nil, fmt.Errorf("sessions: username: %w", err)
				}
				names[c.UserID] = n
			}
		}
		out = append(out, Connection{ConnInfo: c, Username: names[c.UserID]})
	}
	return out, nil
}

// End ends a connection. The actor needs core.sessions.manage and every
// permission the connected account holds, so a moderator cannot end an
// administrator's connection. It is audited.
func (s *Service) End(ctx context.Context, actor int64, id uint64) error {
	c, ok := s.conns.Get(id)
	if !ok {
		return ErrNotFound
	}
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		if c.UserID == 0 {
			err = perm.RequireTx(ctx, tx, actor, perm.SessionsManage)
		} else {
			err = perm.RequireOutranks(ctx, tx, actor, c.UserID, perm.SessionsManage)
		}
		if err != nil {
			return err
		}
		return audit.Record(ctx, tx, s.now(), audit.Entry{
			Actor: actor, Action: audit.ConnectionEnded, TargetType: "user", TargetID: c.UserID, Detail: c.Mode,
		})
	})
	if err != nil {
		return err
	}
	if !s.conns.End(id, &presence.Disconnect{Message: EndedMessage}) {
		return ErrNotFound
	}
	s.log.Info("connection ended by staff", "actor", actor, "user_id", c.UserID, "conn", id)
	return nil
}
