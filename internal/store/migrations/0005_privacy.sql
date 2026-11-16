-- Profile fields, per-field visibility and account erasure
-- (docs/DESIGN.md §5).

CREATE TABLE user_profiles (
    user_id     INTEGER NOT NULL PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    full_name   TEXT    NOT NULL DEFAULT '',
    phone       TEXT    NOT NULL DEFAULT '',
    status_text TEXT    NOT NULL DEFAULT '',
    updated_at  TEXT    NOT NULL
) STRICT;

-- Rows exist only for fields a member has changed from the default.
CREATE TABLE user_visibility (
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    field   TEXT    NOT NULL,
    level   TEXT    NOT NULL CHECK (level IN ('public', 'friends', 'none')),
    PRIMARY KEY (user_id, field)
) STRICT;

-- An erasure request locks the account until erase_after, when the account
-- is erased and completed_at set. The row is kept (with the user row,
-- which becomes an anonymous tombstone) as the record that it happened.
CREATE TABLE erasure_requests (
    user_id        INTEGER NOT NULL PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    requested_at   TEXT    NOT NULL,
    erase_after    TEXT    NOT NULL,
    delete_content INTEGER NOT NULL CHECK (delete_content IN (0, 1)),
    completed_at   TEXT
) STRICT;
