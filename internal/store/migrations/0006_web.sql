-- Web interface login codes and sessions (docs/DESIGN.md §11). Codes and
-- session tokens are stored only as SHA-256 hashes.

-- One-time codes generated in the TUI, valid for a few minutes.
CREATE TABLE web_login_codes (
    code_hash  TEXT    NOT NULL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TEXT    NOT NULL
) STRICT;
CREATE INDEX web_login_codes_user ON web_login_codes (user_id);

CREATE TABLE web_sessions (
    token_hash TEXT    NOT NULL PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf       TEXT    NOT NULL,
    created_at TEXT    NOT NULL,
    expires_at TEXT    NOT NULL
) STRICT;
CREATE INDEX web_sessions_user ON web_sessions (user_id);
