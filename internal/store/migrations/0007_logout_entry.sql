-- Log out is the q key of the main menu (Esc too in full screen), so the
-- separate Log out menu entry is removed, wherever an administrator moved
-- it. Its menu_seeded row stays, so it is never added back.
DELETE FROM menu_entries WHERE target = 'core:logout';
