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
