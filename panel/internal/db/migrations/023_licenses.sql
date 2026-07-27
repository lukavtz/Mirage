ALTER TABLE purchases ADD COLUMN tier TEXT DEFAULT 'starter';
ALTER TABLE purchases ADD COLUMN features TEXT DEFAULT '{}';

CREATE TABLE IF NOT EXISTS license_trials (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE,
    ip TEXT NOT NULL,
    machine_id TEXT DEFAULT '',
    tier TEXT DEFAULT 'starter',
    max_sessions INTEGER DEFAULT 50,
    expires_at TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);
