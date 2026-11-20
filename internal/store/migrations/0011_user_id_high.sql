-- Account IDs are never reused. users.id has no AUTOINCREMENT, so SQLite
-- would give a deleted row's ID (a rejected applicant's, if it was the
-- highest) to the next account, and audit entries about the old account
-- would then read as the new one's. Registration takes the next ID from
-- this one-row table instead. (Rebuilding users with AUTOINCREMENT is not
-- safe: other tables reference it and migrations run with foreign keys
-- on.)
CREATE TABLE user_id_high (
    one  INTEGER PRIMARY KEY CHECK (one = 1),
    high INTEGER NOT NULL
) STRICT;

-- Start above every ID in use or recorded, including applicants already
-- rejected and known only to the audit log.
INSERT INTO user_id_high (one, high) VALUES (1, max(
    (SELECT COALESCE(MAX(id), 0) FROM users),
    (SELECT COALESCE(MAX(actor_id), 0) FROM audit_log),
    (SELECT COALESCE(MAX(CAST(target_id AS INTEGER)), 0) FROM audit_log WHERE target_type = 'user')
));

-- Any insert (registration, or one with an explicit ID) moves the mark up.
CREATE TRIGGER user_id_high_insert AFTER INSERT ON users BEGIN
    UPDATE user_id_high SET high = NEW.id WHERE NEW.id > high;
END;
