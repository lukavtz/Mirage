ALTER TABLE builds ADD COLUMN user_id TEXT DEFAULT NULL;
CREATE INDEX idx_builds_user ON builds(user_id);
