-- System-wide key/value settings managed from the admin menu
-- (e.g. BBS name and other branding, see docs/DESIGN.md §15).
CREATE TABLE system_settings (
    key        TEXT NOT NULL PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
