# PostgreSQL Verification and Safe Performance Design

## Goal

Fully verify the panel against PostgreSQL 16 in Docker and apply safe, measurable optimizations for a balanced workload: ingestion bursts, dashboard reads, search, downloads, and tenant-isolated API access.

## Boundaries

Included: Docker PostgreSQL lifecycle, canonical migrations, pool lifetime configuration, PostgreSQL search support (`pg_trgm` plus targeted indexes), PostgreSQL syntax verification/fixes, deterministic integration and query-plan tests, API smoke tests, backup/restore verification, and GitHub CI/PR preparation.

Excluded from this cycle: ingest batching, N+1 query redesign, materialized statistics, broad API response changes, or deleting the legacy SQLite backup. The isolated `tools/legacy-import` SQLite reader remains operator-only and outside the panel module/image.

## Architecture

The panel remains a Go `database/sql` application using pgx/v5 stdlib and one shared PostgreSQL pool. `DATABASE_URL` is mandatory; `DB_PROVIDER` and `DB_PATH` remain rejected. PostgreSQL 16 runs in Compose without host-port exposure. Existing per-file transactional migrations and `_migrations` SHA-256 verification remain the schema authority.

The pool keeps bounded `MaxOpenConns`/`MaxIdleConns` and adds a finite connection lifetime shorter than common infrastructure idle limits. The exact value is 30 minutes unless deployment constraints require a lower value; it must be covered by a deterministic configuration test.

Search optimization uses `CREATE EXTENSION IF NOT EXISTS pg_trgm` and GIN trigram indexes only on columns used by existing case-insensitive substring searches. Indexes are added through a numbered migration and are idempotent. No user input is interpolated into DDL or queries. Existing parameterized helper calls remain the only data-query path.

## Verification

A disposable PostgreSQL 16 service is started before tests. The deterministic suite must:

- run every canonical migration on an empty schema;
- run migrations a second time and assert no migration rows are added;
- verify expected tables, extension, indexes, and migration hashes;
- execute representative search/data/stats queries and validate PostgreSQL syntax;
- run `EXPLAIN (FORMAT JSON)` for targeted substring searches and assert the intended trigram index appears in the plan for a sufficiently selective fixture;
- exercise login, session ingestion, session listing/search, build creation with `RETURNING`, file/screenshot access, tenant isolation, and LISTEN/NOTIFY where the existing fixtures support them;
- create a custom-format dump, restore it to a disposable database, and compare deterministic table counts/checksums;
- verify startup fails without `DATABASE_URL`, invalid URLs fail, and legacy provider variables are rejected.

Commands: `go test -count=1 ./internal/...`, `go test -race ./internal/...`, `go vet ./...`, `go build ./...`, isolated tool `go test ./...`, `docker compose config`, `docker compose build`, and a Compose health/API smoke run with secrets supplied through environment variables only.

## Security

Do not publish PostgreSQL ports. Do not put passwords in manifests, logs, commits, or PR comments. Backup manifests contain only redacted connection metadata and checksums. File-copy tooling rejects symlinks and path traversal. Backup restore is performed in a disposable target and never overwrites the only backup.

## GitHub

The repository currently has no local `.git` metadata and `gh` authentication/remote state is unavailable. Preserve unrelated working-tree changes. After verification, inspect for repository metadata again; commit/push/PR is attempted only when a verified remote and authenticated GitHub CLI are available. Otherwise report the exact blocker and retain verification artifacts locally.
