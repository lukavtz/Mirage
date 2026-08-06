CREATE TABLE IF NOT EXISTS sales_leads (
    id TEXT PRIMARY KEY,
    telegram_id TEXT NOT NULL,
    username TEXT DEFAULT '',
    tier TEXT NOT NULL,
    status TEXT DEFAULT 'new',
    referral_code TEXT DEFAULT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
