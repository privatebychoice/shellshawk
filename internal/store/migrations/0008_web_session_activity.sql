-- When each web session was last used, so staff can see who is online on
-- the web (updated at most once a minute), and a random public ID that
-- names the session to staff without revealing its token. Both are
-- deleted with the session.
ALTER TABLE web_sessions ADD COLUMN last_seen_at TEXT;
ALTER TABLE web_sessions ADD COLUMN public_id TEXT;
UPDATE web_sessions SET public_id = lower(hex(randomblob(9)));
CREATE UNIQUE INDEX web_sessions_public_id ON web_sessions (public_id);
