CREATE TABLE IF NOT EXISTS filter_presets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    domains TEXT NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO filter_presets (id, name, domains) VALUES
    ('steam', 'Steam', '["steamcommunity.com","store.steampowered.com","help.steampowered.com"]'),
    ('crypto', 'Crypto', '["binance.com","coinbase.com","kraken.com","bybit.com","okx.com","huobi.com","crypto.com","gemini.com","kucoin.com"]'),
    ('email', 'Email', '["mail.google.com","outlook.live.com","yahoo.com","protonmail.com","mail.yandex.com","tutanota.com"]'),
    ('social', 'Social', '["facebook.com","twitter.com","instagram.com","reddit.com","discord.com","tiktok.com","linkedin.com"]'),
    ('gaming', 'Gaming', '["epicgames.com","ubisoft.com","ea.com","battle.net","riotgames.com","minecraft.net","roblox.com"]')
ON CONFLICT (id) DO NOTHING;
