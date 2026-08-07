# PostgreSQL cutover

Run this temporary, operator-run one-shot tool before the write freeze; panel startup never invokes it and the Docker build does not include it. `SOURCE` is the current PostgreSQL URL or a legacy SQLite path, and `TARGET_DATABASE_URL` is the disposable PostgreSQL target. This tool has no SQLite driver: for a SQLite path it only creates an immutable file copy; use `tools/legacy-import` for SQLite table reads and migration.

```sh
cd tools/postgresql-cutover
go run . \
  -source "$SOURCE" \
  -target "$TARGET_DATABASE_URL" \
  -backup-dir /secure/backups \
  -manifest /secure/backups/cutover-manifest.json \
  -copy-root /srv/panel/data/screenshots \
  -copy-root /srv/panel/data/sessions \
  -copy-root /srv/panel/data/icons
```

The command refuses missing or identical endpoints, runs `pg_dump --format=custom --no-owner` for PostgreSQL sources (or makes an immutable SQLite file copy), hashes the backup, rejects symlinks in copied roots, and writes host/database metadata without credentials.


## Backup verification

After `docker compose --profile backup run --rm backup`, verify the newest dump
in a disposable PostgreSQL 16 container without touching the production volume:

```sh
COMPOSE_PROJECT_NAME=panel \
  BACKUP_VERIFY_VOLUME=panel_panel-backups \
  BACKUP_VERIFY_NETWORK=panel_default \
  ./tools/verify-backup.sh
```

The verifier restores with `pg_restore --clean --if-exists --no-owner`, checks
that the public schema contains tables, and removes only its disposable
container on exit. It never logs a database URL or password.

## Production environment

Provide secrets outside the repository. For production, set
`APP_ENV=production`, `JWT_SECRET`, `DATABASE_URL`, `DB_PASSWORD`,
`TLS_ENABLED=true`, `TLS_SELF_SIGNED=false`, `TLS_CERT_FILE`, and
`TLS_KEY_FILE`; mount the certificate and key read-only at those paths.

For scheduled backups, set `BACKUP_RETENTION_DAYS` to a non-negative integer.
Set `BACKUP_OFFSITE_DIR` to a mounted directory synchronized by the operator
to durable off-host storage, and set `BACKUP_OFFSITE_REQUIRED=true` so a
missing off-host mount fails the backup instead of silently retaining only a
local copy. The backup container performs `pg_dump`, validates the custom dump
with `pg_restore --list`, prunes dumps older than the retention window, and
copies the current dump to the off-host mount.