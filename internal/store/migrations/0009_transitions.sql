-- Transition screens: text art shown between the menu and an application
-- (docs/DESIGN.md §6.5).

-- A transition profile is a named set of text files, served over SFTP as
-- /text/<slug>/. mode 'random' shows a random file each time; 'single'
-- always shows the file named in file.
CREATE TABLE transition_profiles (
    id         INTEGER PRIMARY KEY,
    slug       TEXT    NOT NULL UNIQUE,
    mode       TEXT    NOT NULL DEFAULT 'random' CHECK (mode IN ('random', 'single')),
    file       TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL
) STRICT;

CREATE TABLE transition_files (
    profile_id INTEGER NOT NULL REFERENCES transition_profiles (id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    updated_at TEXT    NOT NULL,
    PRIMARY KEY (profile_id, name)
) STRICT;

-- Which profile is shown at each transition point: entering a menu item
-- ('enter') or returning from it to the menu ('exit'). target is a menu
-- item ("<owner>:<key>") or '*', the default for items without their own.
-- A NULL profile_id means "show nothing here", overriding the default.
-- Deleting a profile removes its rows, so those points fall back to the
-- default again.
CREATE TABLE transition_points (
    target     TEXT    NOT NULL,
    moment     TEXT    NOT NULL CHECK (moment IN ('enter', 'exit')),
    profile_id INTEGER REFERENCES transition_profiles (id) ON DELETE CASCADE,
    PRIMARY KEY (target, moment)
) STRICT;

-- Members can turn transition screens off in their display settings.
ALTER TABLE user_prefs ADD COLUMN transitions INTEGER NOT NULL DEFAULT 1 CHECK (transitions IN (0, 1));
