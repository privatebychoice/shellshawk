-- Accounts, SSH keys, groups/permissions, invites and the audit log
-- (docs/DESIGN.md §4). Timestamps are RFC 3339 UTC text.

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT    NOT NULL,           -- argon2id, PHC string format
    email         TEXT,
    status        TEXT    NOT NULL CHECK (status IN ('pending', 'active', 'locked')),
    created_at    TEXT    NOT NULL,
    approved_at   TEXT,
    approved_by   INTEGER REFERENCES users (id) ON DELETE SET NULL,
    last_login_at TEXT,
    invite_id     INTEGER REFERENCES invites (id) ON DELETE SET NULL
) STRICT;

CREATE INDEX users_status ON users (status);

-- A key belongs to at most one account (fingerprint is globally unique).
CREATE TABLE user_keys (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    fingerprint  TEXT    NOT NULL UNIQUE,     -- SHA256:… as printed by ssh-keygen -l
    key_type     TEXT    NOT NULL,
    public_key   TEXT    NOT NULL,            -- authorized_keys format, no comment
    label        TEXT    NOT NULL DEFAULT '',
    created_at   TEXT    NOT NULL,
    last_used_at TEXT
) STRICT;

CREATE INDEX user_keys_user ON user_keys (user_id);

-- "groups" is avoided as a table name because GROUPS is an SQL keyword.
CREATE TABLE access_groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL COLLATE NOCASE UNIQUE,
    description TEXT    NOT NULL DEFAULT '',
    builtin     INTEGER NOT NULL DEFAULT 0 CHECK (builtin IN (0, 1)),
    created_at  TEXT    NOT NULL
) STRICT;

CREATE TABLE access_group_permissions (
    group_id   INTEGER NOT NULL REFERENCES access_groups (id) ON DELETE CASCADE,
    permission TEXT    NOT NULL,
    PRIMARY KEY (group_id, permission)
) STRICT;

CREATE TABLE user_access_groups (
    user_id  INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES access_groups (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
) STRICT;

CREATE INDEX user_access_groups_group ON user_access_groups (group_id);

-- Invite codes are stored only as SHA-256 hashes (codes are 128-bit random,
-- so a fast hash is sufficient).
CREATE TABLE invites (
    id               INTEGER PRIMARY KEY,
    code_hash        TEXT    NOT NULL UNIQUE,
    created_by       INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at       TEXT    NOT NULL,
    expires_at       TEXT,
    max_uses         INTEGER NOT NULL CHECK (max_uses >= 1),
    uses             INTEGER NOT NULL DEFAULT 0 CHECK (uses >= 0),
    require_approval INTEGER NOT NULL CHECK (require_approval IN (0, 1)),
    note             TEXT    NOT NULL DEFAULT '',
    revoked_at       TEXT
) STRICT;

-- Groups granted to accounts registered with an invite. None → "member".
CREATE TABLE invite_groups (
    invite_id INTEGER NOT NULL REFERENCES invites (id) ON DELETE CASCADE,
    group_id  INTEGER NOT NULL REFERENCES access_groups (id) ON DELETE CASCADE,
    PRIMARY KEY (invite_id, group_id)
) STRICT;

-- actor_id has no foreign key so entries outlive the account; erasure
-- (stage 9) rewrites it to a tombstone. Purged after the retention period.
CREATE TABLE audit_log (
    id          INTEGER PRIMARY KEY,
    at          TEXT    NOT NULL,
    actor_id    INTEGER,
    action      TEXT    NOT NULL,
    target_type TEXT    NOT NULL DEFAULT '',
    target_id   TEXT    NOT NULL DEFAULT '',
    detail      TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX audit_log_at ON audit_log (at);

-- Built-in groups and their core permissions.
INSERT INTO access_groups (name, description, builtin, created_at) VALUES
    ('admin',     'Full system administration',              1, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    ('moderator', 'Approves accounts and issues invites',    1, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    ('member',    'Default group for registered accounts',   1, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));

INSERT INTO access_group_permissions (group_id, permission)
    SELECT id, 'core.admin' FROM access_groups WHERE name = 'admin';

INSERT INTO access_group_permissions (group_id, permission)
    SELECT g.id, p.permission
    FROM access_groups g,
         (SELECT 'core.users.approve' AS permission UNION ALL SELECT 'core.invite.create') p
    WHERE g.name = 'moderator';
