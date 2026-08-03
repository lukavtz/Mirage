CREATE TABLE IF NOT EXISTS screenshots (
  id         TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  file_path  TEXT NOT NULL,
  mime_type  TEXT NOT NULL DEFAULT 'image/bmp',
  size_bytes INTEGER NOT NULL,
  width      INTEGER NOT NULL DEFAULT 0,
  height     INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(session_id)
);
CREATE INDEX IF NOT EXISTS idx_screenshots_session ON screenshots(session_id);
