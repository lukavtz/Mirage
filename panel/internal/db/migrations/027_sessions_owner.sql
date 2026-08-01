ALTER TABLE sessions ADD COLUMN owner_id TEXT DEFAULT NULL;
CREATE INDEX idx_sessions_owner ON sessions(owner_id);
