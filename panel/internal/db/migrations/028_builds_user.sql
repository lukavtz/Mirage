ALTER TABLE builds ADD COLUMN user_id TEXT DEFAULT NULL;
CREATE INDEX IF NOT EXISTS idx_builds_user ON builds(user_id) WHERE user_id IS NOT NULL;
