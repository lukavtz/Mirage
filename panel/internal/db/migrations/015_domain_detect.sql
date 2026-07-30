CREATE TABLE IF NOT EXISTS domain_detect (
    id TEXT PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,
    tag TEXT NOT NULL,
    color TEXT DEFAULT '#5865F2',
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS session_tags (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    tag TEXT NOT NULL,
    color TEXT DEFAULT '#5865F2',
    created_at TEXT DEFAULT (datetime('now'))
);
