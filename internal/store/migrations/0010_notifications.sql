-- Notifications: short notices for a member about something that happened
-- elsewhere (a page, a new private message, a reply to their thread),
-- shown between screens and listed under Notifications
-- (docs/DESIGN.md §6.6).

-- kind is "<plugin>:<key>", declared by the plugin. actor_id is who caused
-- it (NULL once that account is gone). text is a short description such
-- as a message subject; ref lets the plugin open the thing (e.g. a message
-- ID). seen_at is set once the member has been shown it.
CREATE TABLE notifications (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL,
    actor_id   INTEGER REFERENCES users (id) ON DELETE SET NULL,
    text       TEXT    NOT NULL DEFAULT '',
    ref        TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL,
    seen_at    TEXT
) STRICT;
CREATE INDEX notifications_user ON notifications (user_id, created_at);
CREATE INDEX notifications_actor ON notifications (actor_id);

-- A member's choice for one kind of notification. No row = the kind's
-- default.
CREATE TABLE notification_settings (
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    kind    TEXT    NOT NULL,
    enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
    PRIMARY KEY (user_id, kind)
) STRICT, WITHOUT ROWID;

-- Show new notifications between screens (when opening a menu item and
-- when returning to the menu).
ALTER TABLE user_prefs ADD COLUMN notifications INTEGER NOT NULL DEFAULT 1 CHECK (notifications IN (0, 1));
