CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('rate_limit', '100');
INSERT OR IGNORE INTO settings (key, value) VALUES ('telegram_token', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('telegram_chat_id', '');
