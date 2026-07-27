CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL,
    price_cents INTEGER NOT NULL,
    product_type TEXT NOT NULL,
    file_data BLOB DEFAULT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS purchases (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    product_id TEXT NOT NULL,
    license_key TEXT NOT NULL UNIQUE,
    activated_at TEXT DEFAULT NULL,
    expires_at TEXT DEFAULT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);
