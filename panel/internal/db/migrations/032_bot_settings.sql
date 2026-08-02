-- Add telegram_id to users for bot registration tracking
ALTER TABLE users ADD COLUMN telegram_id TEXT DEFAULT NULL;
CREATE INDEX IF NOT EXISTS idx_users_telegram ON users(telegram_id);

-- Bot settings
INSERT OR IGNORE INTO settings (key, value) VALUES ('panel_url', 'http://localhost:8080');
INSERT OR IGNORE INTO settings (key, value) VALUES ('bot_admin_chat_id', '');

-- Purchase requests from bot
CREATE TABLE IF NOT EXISTS purchase_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    tier TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    admin_chat_id INTEGER DEFAULT 0,
    admin_message_id INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_purchase_requests_user ON purchase_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_purchase_requests_status ON purchase_requests(status);
