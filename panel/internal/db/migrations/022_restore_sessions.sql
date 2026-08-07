CREATE TABLE IF NOT EXISTS restore_sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    cookies_json TEXT NOT NULL,
    proxy_config TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    access_token TEXT DEFAULT NULL,
    error TEXT DEFAULT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
