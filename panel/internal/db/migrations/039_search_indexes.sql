CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;

CREATE INDEX IF NOT EXISTS idx_passwords_search_trgm
    ON passwords USING gin (
        url public.gin_trgm_ops,
        username public.gin_trgm_ops,
        password_value public.gin_trgm_ops
    );

CREATE INDEX IF NOT EXISTS idx_cookies_search_trgm
    ON cookies USING gin (
        name public.gin_trgm_ops,
        domain public.gin_trgm_ops,
        value public.gin_trgm_ops
    );

CREATE INDEX IF NOT EXISTS idx_cards_search_trgm
    ON cards USING gin (
        holder public.gin_trgm_ops,
        number public.gin_trgm_ops
    );

CREATE INDEX IF NOT EXISTS idx_wallets_search_trgm
    ON wallets USING gin (
        name public.gin_trgm_ops,
        path public.gin_trgm_ops
    );
