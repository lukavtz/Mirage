ALTER TABLE sessions ADD COLUMN owner_id TEXT DEFAULT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_owner ON sessions(owner_id) WHERE owner_id IS NOT NULL;
