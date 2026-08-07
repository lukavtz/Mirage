CREATE TABLE IF NOT EXISTS referrals (
    id                TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    referrer_id       TEXT NOT NULL,
    referred_user_id  TEXT NOT NULL,
    code              TEXT,
    applied_at        TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id);
