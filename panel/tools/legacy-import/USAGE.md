# Legacy import

This temporary, operator-run module is the only SQLite reader. Run it once against a frozen source and a clean PostgreSQL target; it is not imported by `panel`, is not part of the Docker build, and must not be added to the panel module. Its SQLite driver dependency is intentionally isolated here for the approved legacy migration only.

```sh
cd tools/legacy-import
go run . \
  -source /secure/backups/mirage.db \
  -target "$TARGET_DATABASE_URL" \
  -manifest /secure/backups/legacy-import-manifest.json \
  -copy-from /secure/data \
  -copy-to /srv/panel/data
```

For a PostgreSQL custom dump, use the dump file as `-source`; the tool invokes `pg_restore --no-owner --exit-on-error` and never treats a live PostgreSQL URL as a source. Every SQLite table is discovered, ordered by foreign keys (parents first), inserted with prepared PostgreSQL statements, and verified with deterministic primary-key-ordered row counts and SHA-256 checksums. Any mismatch aborts. Files are copied only under the requested roots; symlink roots or entries are rejected and copied bytes are hashed.
