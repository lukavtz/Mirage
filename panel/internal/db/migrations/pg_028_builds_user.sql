-- PG override of 028_builds_user.sql.
-- Same tenant column, partial index for the same reason as pg_027.
ALTER TABLE builds ADD COLUMN IF NOT EXISTS user_id TEXT DEFAULT NULL;
CREATE INDEX IF NOT EXISTS idx_builds_user ON builds(user_id) WHERE user_id IS NOT NULL;
