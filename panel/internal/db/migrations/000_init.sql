CREATE TABLE IF NOT EXISTS invite_codes (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    code TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'worker',
    tier TEXT NOT NULL DEFAULT 'starter',
    max_uses INTEGER NOT NULL DEFAULT 1,
    used_count INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT DEFAULT NULL,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
