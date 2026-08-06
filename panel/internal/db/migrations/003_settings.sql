CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT INTO settings (key, value) VALUES
    ('rate_limit', '100'),
    ('telegram_token', ''),
    ('telegram_chat_id', '')
ON CONFLICT (key) DO NOTHING;
