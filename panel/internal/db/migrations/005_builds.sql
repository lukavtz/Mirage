CREATE TABLE IF NOT EXISTS builds (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    config_hash TEXT,
    file_size INTEGER,
    file_data BLOB,
    sha256 TEXT,
    build_tag TEXT,
    download_count INTEGER DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
