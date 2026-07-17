CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Default admin user — CHANGE THIS PASSWORD after first login.
-- The hash below is for 'admin'. Generate a new one with:
--   go run cmd/hashpw/main.go yourpassword
INSERT OR IGNORE INTO users (id, username, password_hash, role)
VALUES ('u_admin', 'admin', 'CHANGE_ME_RUN_HASHPW_TOOL', 'admin');
