CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (id, username, password_hash, role)
VALUES ('u_admin', 'admin', '$2a$12$LJ3m4ys3Lk0TSwHnbfOMiOXPm1Qlq5GzGQq5Zrn/gJ6Xvz5Vf5H0e', 'admin');
