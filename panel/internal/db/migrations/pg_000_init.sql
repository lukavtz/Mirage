-- PG init: ensure gen_random_uuid() is available (core since PG 13,
-- pgcrypto covers older deployments). Idempotent.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
