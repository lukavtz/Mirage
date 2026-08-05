CREATE TABLE IF NOT EXISTS referrals (
    id                TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    referrer_id       TEXT NOT NULL,
    referred_user_id  TEXT NOT NULL,
    code              TEXT,
    applied_at        TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id);
