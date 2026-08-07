CREATE TABLE IF NOT EXISTS worker_activity (
    id         TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    user_id    TEXT NOT NULL,
    action     TEXT NOT NULL,
    target_id  TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_worker_activity_user ON worker_activity(user_id, created_at DESC);
