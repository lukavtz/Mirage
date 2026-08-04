-- PG override of 027_sessions_owner.sql.
-- Adds the tenant column like the base migration, but with a PARTIAL
-- index: tenant-scoped queries filter owner_id = $user, and the vast
-- majority of rows (legacy sessions) have NULL owner, so the partial
-- index is far smaller and faster than the blanket one.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS owner_id TEXT DEFAULT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_owner ON sessions(owner_id) WHERE owner_id IS NOT NULL;
