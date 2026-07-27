CREATE TABLE bans (
    id        TEXT PRIMARY KEY,
    ip        TEXT NOT NULL,
    reason    TEXT,
    banned_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_bans_ip ON bans(ip);
