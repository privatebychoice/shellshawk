package perm

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"go.privatebychoice.com/shellshawk/internal/audit"
	"go.privatebychoice.com/shellshawk/internal/store"
)

// Errors returned by Service.
var (
	ErrForbidden    = errors.New("permission denied")
	ErrNotFound     = errors.New("not found")
	ErrExists       = errors.New("already exists")
	ErrProtected    = errors.New("built-in group cannot be changed this way")
	ErrLastAdmin    = errors.New("would leave no active administrator")
	ErrUnknownPerm  = errors.New("unknown permission")
	ErrInvalidGroup = errors.New("invalid group name")
)

// Built-in group names (seeded by migration 0002).
const (
	GroupAdmin     = "admin"
	GroupModerator = "moderator"
	GroupMember    = "member"
)

var groupName = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,31}$`)

// Group is an access group and its permissions.
type Group struct {
	ID          int64
	Name        string
	Description string
	Builtin     bool
	Permissions []string
}

// Service manages groups and answers permission checks.
type Service struct {
	db  *sql.DB
	reg *Registry
	now func() time.Time
	log *slog.Logger
}

// NewService returns a Service. now may be nil (time.Now).
func NewService(db *sql.DB, reg *Registry, now func() time.Time, log *slog.Logger) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, reg: reg, now: now, log: log.With("component", "perm")}
}

// Registry returns the permission registry.
func (s *Service) Registry() *Registry { return s.reg }

// Permissions returns userID's effective permissions. Accounts that are not
// active have none.
func (s *Service) Permissions(ctx context.Context, userID int64) (Set, error) {
	return permissions(ctx, s.db, userID)
}

func permissions(ctx context.Context, db store.DBTX, userID int64) (Set, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT DISTINCT gp.permission
		FROM users u
		JOIN user_access_groups ug ON ug.user_id = u.id
		JOIN access_group_permissions gp ON gp.group_id = ug.group_id
		WHERE u.id = ? AND u.status = 'active'`, userID)
	if err != nil {
		return nil, fmt.Errorf("perm: query permissions: %w", err)
	}
	defer rows.Close()
	set := Set{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, fmt.Errorf("perm: scan permission: %w", err)
		}
		set[p] = true
	}
	return set, rows.Err()
}

// Has reports whether userID holds p.
func (s *Service) Has(ctx context.Context, userID int64, p string) (bool, error) {
	set, err := s.Permissions(ctx, userID)
	if err != nil {
		return false, err
	}
	return set.Has(p), nil
}

// Require returns ErrForbidden unless userID holds p.
func (s *Service) Require(ctx context.Context, userID int64, p string) error {
	ok, err := s.Has(ctx, userID, p)
	if err != nil {
		return err
	}
	if !ok {
		s.log.Info("permission denied", "user_id", userID, "permission", p)
		return ErrForbidden
	}
	return nil
}

// RequireTx is Require inside a transaction.
func RequireTx(ctx context.Context, tx store.DBTX, userID int64, p string) error {
	set, err := permissions(ctx, tx, userID)
	if err != nil {
		return err
	}
	if !set.Has(p) {
		return ErrForbidden
	}
	return nil
}

// ---- groups --------------------------------------------------------------

// Groups lists all groups with their permissions.
func (s *Service) Groups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, description, builtin FROM access_groups ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("perm: list groups: %w", err)
	}
	var groups []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Builtin); err != nil {
			rows.Close()
			return nil, fmt.Errorf("perm: scan group: %w", err)
		}
		groups = append(groups, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range groups {
		if groups[i].Permissions, err = groupPerms(ctx, s.db, groups[i].ID); err != nil {
			return nil, err
		}
	}
	return groups, nil
}

// GroupByName returns the named group.
func (s *Service) GroupByName(ctx context.Context, name string) (Group, error) {
	return groupByName(ctx, s.db, name)
}

func groupByName(ctx context.Context, db store.DBTX, name string) (Group, error) {
	var g Group
	err := db.QueryRowContext(ctx, `SELECT id, name, description, builtin FROM access_groups WHERE name = ?`, name).
		Scan(&g.ID, &g.Name, &g.Description, &g.Builtin)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, fmt.Errorf("perm: group %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return Group{}, fmt.Errorf("perm: get group: %w", err)
	}
	g.Permissions, err = groupPerms(ctx, db, g.ID)
	return g, err
}

func groupByID(ctx context.Context, db store.DBTX, id int64) (Group, error) {
	var g Group
	err := db.QueryRowContext(ctx, `SELECT id, name, description, builtin FROM access_groups WHERE id = ?`, id).
		Scan(&g.ID, &g.Name, &g.Description, &g.Builtin)
	if errors.Is(err, sql.ErrNoRows) {
		return Group{}, fmt.Errorf("perm: group %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return Group{}, fmt.Errorf("perm: get group: %w", err)
	}
	g.Permissions, err = groupPerms(ctx, db, g.ID)
	return g, err
}

func groupPerms(ctx context.Context, db store.DBTX, groupID int64) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT permission FROM access_group_permissions WHERE group_id = ? ORDER BY permission`, groupID)
	if err != nil {
		return nil, fmt.Errorf("perm: group permissions: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GroupByID returns the group with id.
func (s *Service) GroupByID(ctx context.Context, id int64) (Group, error) {
	return groupByID(ctx, s.db, id)
}

// Member is a group member.
type Member struct {
	UserID   int64
	Username string
	Status   string
}

// GroupMembers lists a group's members by username.
func (s *Service) GroupMembers(ctx context.Context, groupID int64) ([]Member, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT u.id, u.username, u.status FROM user_access_groups ug JOIN users u ON u.id = ug.user_id
		WHERE ug.group_id = ? ORDER BY u.username`, groupID)
	if err != nil {
		return nil, fmt.Errorf("perm: group members: %w", err)
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Username, &m.Status); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// UserGroups returns the names of userID's groups.
func (s *Service) UserGroups(ctx context.Context, userID int64) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT g.name FROM user_access_groups ug JOIN access_groups g ON g.id = ug.group_id
		WHERE ug.user_id = ? ORDER BY g.name`, userID)
	if err != nil {
		return nil, fmt.Errorf("perm: user groups: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// holdsAll reports whether actor's permissions cover every permission in
// perms. This stops an actor granting access they do not have themselves.
func holdsAll(actor Set, perms []string) bool {
	for _, p := range perms {
		if !actor.Has(p) {
			return false
		}
	}
	return true
}

// actorFor loads actor's permissions in tx and checks GroupsManage.
func actorFor(ctx context.Context, tx store.DBTX, actor int64) (Set, error) {
	set, err := permissions(ctx, tx, actor)
	if err != nil {
		return nil, err
	}
	if !set.Has(GroupsManage) {
		return nil, ErrForbidden
	}
	return set, nil
}

// CreateGroup creates an empty group.
func (s *Service) CreateGroup(ctx context.Context, actor int64, name, description string) (int64, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if !groupName.MatchString(name) {
		return 0, ErrInvalidGroup
	}
	var id int64
	err := store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := actorFor(ctx, tx, actor); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO access_groups (name, description, builtin, created_at) VALUES (?, ?, 0, ?)
			ON CONFLICT (name) DO NOTHING`, name, strings.TrimSpace(description), store.FormatTime(s.now()))
		if err != nil {
			return fmt.Errorf("perm: create group: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrExists
		}
		id, _ = res.LastInsertId()
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: audit.GroupCreated, TargetType: "group", TargetID: id, Detail: name})
	})
	if err == nil {
		s.log.Info("group created", "actor", actor, "group", name)
	}
	return id, err
}

// DeleteGroup deletes a non-built-in group the actor fully outranks.
func (s *Service) DeleteGroup(ctx context.Context, actor, groupID int64) error {
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		set, err := actorFor(ctx, tx, actor)
		if err != nil {
			return err
		}
		checkAdmins, err := adminGuard(ctx, tx)
		if err != nil {
			return err
		}
		g, err := groupByID(ctx, tx, groupID)
		if err != nil {
			return err
		}
		if g.Builtin {
			return ErrProtected
		}
		if !holdsAll(set, g.Permissions) {
			return ErrForbidden
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM access_groups WHERE id = ?`, groupID); err != nil {
			return fmt.Errorf("perm: delete group: %w", err)
		}
		if err := checkAdmins(); err != nil {
			return err
		}
		s.log.Info("group deleted", "actor", actor, "group", g.Name)
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: audit.GroupDeleted, TargetType: "group", TargetID: groupID, Detail: g.Name})
	})
}

// Grant adds permission p to a group. The actor must hold p.
func (s *Service) Grant(ctx context.Context, actor, groupID int64, p string) error {
	if !s.reg.Known(p) {
		return fmt.Errorf("%w: %q", ErrUnknownPerm, p)
	}
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		set, err := actorFor(ctx, tx, actor)
		if err != nil {
			return err
		}
		if !set.Has(p) {
			return ErrForbidden
		}
		if _, err := groupByID(ctx, tx, groupID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO access_group_permissions (group_id, permission) VALUES (?, ?)
			ON CONFLICT DO NOTHING`, groupID, p); err != nil {
			return fmt.Errorf("perm: grant: %w", err)
		}
		s.log.Info("permission granted", "actor", actor, "group_id", groupID, "permission", p)
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: audit.GroupGranted, TargetType: "group", TargetID: groupID, Detail: p})
	})
}

// Revoke removes permission p from a group. The admin group always keeps
// core.admin.
func (s *Service) Revoke(ctx context.Context, actor, groupID int64, p string) error {
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		set, err := actorFor(ctx, tx, actor)
		if err != nil {
			return err
		}
		checkAdmins, err := adminGuard(ctx, tx)
		if err != nil {
			return err
		}
		if !set.Has(p) {
			return ErrForbidden
		}
		g, err := groupByID(ctx, tx, groupID)
		if err != nil {
			return err
		}
		if g.Builtin && g.Name == GroupAdmin && p == Admin {
			return ErrProtected
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM access_group_permissions WHERE group_id = ? AND permission = ?`, groupID, p); err != nil {
			return fmt.Errorf("perm: revoke: %w", err)
		}
		if err := checkAdmins(); err != nil {
			return err
		}
		s.log.Info("permission revoked", "actor", actor, "group_id", groupID, "permission", p)
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: audit.GroupRevoked, TargetType: "group", TargetID: groupID, Detail: p})
	})
}

// AddMember puts userID in a group. The actor must hold every permission the
// group grants.
func (s *Service) AddMember(ctx context.Context, actor, groupID, userID int64) error {
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		set, err := actorFor(ctx, tx, actor)
		if err != nil {
			return err
		}
		g, err := groupByID(ctx, tx, groupID)
		if err != nil {
			return err
		}
		if !holdsAll(set, g.Permissions) {
			return ErrForbidden
		}
		if err := AddMemberSystem(ctx, tx, userID, groupID); err != nil {
			return err
		}
		s.log.Info("group member added", "actor", actor, "group", g.Name, "user_id", userID)
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: audit.GroupMemberAdded, TargetType: "user", TargetID: userID, Detail: g.Name})
	})
}

// RemoveMember takes userID out of a group, refusing to remove the last
// active administrator.
func (s *Service) RemoveMember(ctx context.Context, actor, groupID, userID int64) error {
	return store.WithTx(ctx, s.db, func(tx *sql.Tx) error {
		set, err := actorFor(ctx, tx, actor)
		if err != nil {
			return err
		}
		checkAdmins, err := adminGuard(ctx, tx)
		if err != nil {
			return err
		}
		g, err := groupByID(ctx, tx, groupID)
		if err != nil {
			return err
		}
		if !holdsAll(set, g.Permissions) {
			return ErrForbidden
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM user_access_groups WHERE user_id = ? AND group_id = ?`, userID, groupID)
		if err != nil {
			return fmt.Errorf("perm: remove member: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if err := checkAdmins(); err != nil {
			return err
		}
		s.log.Info("group member removed", "actor", actor, "group", g.Name, "user_id", userID)
		return audit.Record(ctx, tx, s.now(), audit.Entry{Actor: actor, Action: audit.GroupMemberRemoved, TargetType: "user", TargetID: userID, Detail: g.Name})
	})
}

// AddMemberSystem adds a membership without actor checks or auditing. It is
// for use inside other services' transactions (registration, bootstrap)
// that do their own checks and auditing.
func AddMemberSystem(ctx context.Context, tx store.DBTX, userID, groupID int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO user_access_groups (user_id, group_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, userID, groupID)
	if err != nil {
		return fmt.Errorf("perm: add member: %w", err)
	}
	return nil
}

// CountActiveAdmins returns how many active accounts hold core.admin.
func CountActiveAdmins(ctx context.Context, db store.DBTX) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `
		SELECT count(DISTINCT u.id)
		FROM users u
		JOIN user_access_groups ug ON ug.user_id = u.id
		JOIN access_group_permissions gp ON gp.group_id = ug.group_id
		WHERE u.status = 'active' AND gp.permission = ?`, Admin).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("perm: count admins: %w", err)
	}
	return n, nil
}

// adminGuard records the number of active administrators before a change.
// Calling the returned check after the change fails the transaction if the
// change removed the last one.
func adminGuard(ctx context.Context, tx store.DBTX) (func() error, error) {
	before, err := CountActiveAdmins(ctx, tx)
	if err != nil {
		return nil, err
	}
	return func() error {
		after, err := CountActiveAdmins(ctx, tx)
		if err != nil {
			return err
		}
		if before > 0 && after == 0 {
			return ErrLastAdmin
		}
		return nil
	}, nil
}

// RequireOutranks fails with ErrForbidden unless actor holds p and every
// permission target's groups grant (regardless of target's status). It stops
// a moderator acting against an administrator.
func RequireOutranks(ctx context.Context, tx store.DBTX, actor, target int64, p string) error {
	set, err := permissions(ctx, tx, actor)
	if err != nil {
		return err
	}
	if !set.Has(p) {
		return ErrForbidden
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT DISTINCT gp.permission
		FROM user_access_groups ug JOIN access_group_permissions gp ON gp.group_id = ug.group_id
		WHERE ug.user_id = ?`, target)
	if err != nil {
		return fmt.Errorf("perm: target permissions: %w", err)
	}
	defer rows.Close()
	var targetPerms []string
	for rows.Next() {
		var tp string
		if err := rows.Scan(&tp); err != nil {
			return err
		}
		targetPerms = append(targetPerms, tp)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if !holdsAll(set, targetPerms) {
		return ErrForbidden
	}
	return nil
}

// AdminGuard is the exported form of adminGuard for other services'
// transactions (e.g. locking an account).
func AdminGuard(ctx context.Context, tx store.DBTX) (func() error, error) { return adminGuard(ctx, tx) }
