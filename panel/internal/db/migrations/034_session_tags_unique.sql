-- Enforce the (session_id, tag) uniqueness that AutoTag relies on via
-- ON CONFLICT (session_id, tag) DO NOTHING. Migration 015 promised the
-- unique key but never created it, so tags could be lost.
-- Deduplicate first, then the unique index becomes the conflict target.
DELETE FROM session_tags
WHERE id NOT IN (SELECT MIN(id) FROM session_tags GROUP BY session_id, tag);

CREATE UNIQUE INDEX IF NOT EXISTS idx_session_tags_unique
    ON session_tags(session_id, tag);
