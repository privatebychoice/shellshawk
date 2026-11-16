-- Configurable menus and plugin settings (docs/DESIGN.md §3.1, §3.2).

-- The member menu tree. parent_id NULL = the main menu. kind 'item' runs a
-- registered menu item ("<owner>:<key>", e.g. "core:settings"); 'submenu'
-- holds child entries. permission, if set, is required in addition to the
-- item's own permissions.
CREATE TABLE menu_entries (
    id         INTEGER PRIMARY KEY,
    parent_id  INTEGER REFERENCES menu_entries (id) ON DELETE CASCADE,
    position   INTEGER NOT NULL,
    label      TEXT    NOT NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('item', 'submenu')),
    target     TEXT    NOT NULL DEFAULT '',
    permission TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL
) STRICT;

CREATE INDEX menu_entries_parent ON menu_entries (parent_id, position);

-- Menu items already added to the menu automatically once. An item an
-- administrator removes is not added back on the next start.
CREATE TABLE menu_seeded (
    target TEXT NOT NULL PRIMARY KEY
) STRICT;

-- Administrator-editable plugin settings, validated against each plugin's
-- declared fields.
CREATE TABLE plugin_settings (
    plugin_id  TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (plugin_id, key)
) STRICT;

-- Plugin permissions already granted to their default groups once.
CREATE TABLE plugin_grants_seeded (
    permission TEXT NOT NULL PRIMARY KEY
) STRICT;

-- The spec gives moderators access to plugin settings.
INSERT INTO access_group_permissions (group_id, permission)
    SELECT id, 'core.plugins.settings' FROM access_groups WHERE name = 'moderator';
