CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    device TEXT DEFAULT '',
    os TEXT DEFAULT '',
    browser TEXT DEFAULT '',
    ip TEXT DEFAULT '',
    location TEXT DEFAULT '',
    last_active_at TEXT DEFAULT (datetime('now')),
    created_at TEXT DEFAULT (datetime('now'))
);
