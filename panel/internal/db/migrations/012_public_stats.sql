INSERT INTO settings (key, value) VALUES
    ('public_stats_enabled', 'false'),
    ('public_stats_tag', '')
ON CONFLICT (key) DO NOTHING;
