-- Per-user display preferences (docs/DESIGN.md §6.2, §6.3, §9).
-- Empty bold/italic means "use the terminal profile's default".
CREATE TABLE user_prefs (
    user_id    INTEGER NOT NULL PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    profile    TEXT    NOT NULL,
    theme      TEXT    NOT NULL,
    bold       TEXT    NOT NULL DEFAULT '',
    italic     TEXT    NOT NULL DEFAULT '',
    ascii_only INTEGER NOT NULL DEFAULT 0 CHECK (ascii_only IN (0, 1)),
    page_size  INTEGER NOT NULL DEFAULT 20 CHECK (page_size BETWEEN 5 AND 200),
    updated_at TEXT    NOT NULL
) STRICT;
