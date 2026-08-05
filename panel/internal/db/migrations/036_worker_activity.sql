CREATE TABLE IF NOT EXISTS worker_activity (
    id         TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id    TEXT NOT NULL,
    action     TEXT NOT NULL,
    target_id  TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_worker_activity_user ON worker_activity(user_id, created_at DESC);
