CREATE TABLE IF NOT EXISTS builds (
    id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    config_hash TEXT,
    file_size INTEGER,
    file_data BYTEA,
    sha256 TEXT,
    build_tag TEXT,
    download_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
