# PostgreSQL Verification and Safe Performance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Verify the panel end-to-end on Docker PostgreSQL 16 and apply balanced, safe, measurable PostgreSQL performance improvements.

**Architecture:** Keep Go `database/sql` with pgx/v5 and the existing canonical migration/hash model. Add only PostgreSQL-native extension/index/pool-lifetime changes, deterministic integration/plan checks, and operator backup/restore checks; preserve API semantics and the isolated legacy importer.

**Tech Stack:** Go 1.25, pgx/v5, PostgreSQL 16 Alpine, Docker Compose, GitHub Actions, `go test`, `go vet`, `go build`, `pg_dump`, `pg_restore`.

## Global Constraints

- `DATABASE_URL` is mandatory; `DB_PROVIDER` and `DB_PATH` must remain rejected.
- PostgreSQL must not publish a host port in Compose.
- No user input may be interpolated into SQL or DDL.
- Do not change ingest batching, N+1 redesign, materialized stats, or API response contracts.
- The legacy SQLite reader may exist only under `tools/legacy-import`, never in the panel module/image.
- Preserve unrelated working-tree changes; do not delete or reset them.
- Every behavioral change gets a failing test before implementation.
- Do not log or commit database passwords, JWT secrets, dumps, or private file data.

---

### Task 1: Start disposable PostgreSQL environment

**Files:**
- Modify: `.env.example` only if required variables are missing
- Inspect: `docker-compose.yml`, `Dockerfile`

**Interfaces:**
- Produces a healthy PostgreSQL 16 service and a disposable test target reachable through the Compose network.

- [ ] **Step 1: Validate Compose interpolation without starting services**

Run from `panel`:

```text
docker compose config
```

Expected: valid rendered services; no `DB_PROVIDER`/`DB_PATH` panel environment; PostgreSQL has no host `ports` mapping.

- [ ] **Step 2: Start PostgreSQL and panel services**

Run with secrets supplied only through the process environment or untracked `.env`:

```text
docker compose up -d postgres panel
```

Expected: `postgres` becomes healthy and `panel` becomes healthy. If an old container/volume conflicts, inspect with `docker compose ps` and stop only this Compose project; never remove unrelated containers or volumes.

- [ ] **Step 3: Verify service health and port isolation**

```text
docker compose ps
docker inspect panel-postgres-1 --format '{{json .NetworkSettings.Ports}}'
```

Expected: PostgreSQL health is `healthy`; published ports are empty/null; panel health endpoint returns HTTP 200 from the host panel port.

- [ ] **Step 4: Commit only environment changes if needed**

Do not commit runtime data, `.env`, dumps, or generated files. Commit only an already-required Compose/env correction with message:

```text
git add docker-compose.yml .env.example
git commit -m "chore: verify postgres compose environment"
```

If no correction is needed, make no commit for this task.

---

### Task 2: Add pool lifetime regression test and safe configuration

**Files:**
- Modify: `internal/db/provider.go`
- Test: `internal/db/provider_test.go` (create if absent)

**Interfaces:**
- `OpenPostgres(connString string) (*sql.DB, error)` remains unchanged.
- The pool must expose a finite `ConnMaxLifetime` of 30 minutes and retain bounded open/idle limits.

- [ ] **Step 1: Write the failing test**

Add a unit-level configuration seam or testable constant and assert:

```go
func TestPoolSettingsHaveFiniteLifetime(t *testing.T) {
    if postgresConnMaxLifetime <= 0 || postgresConnMaxLifetime > 30*time.Minute {
        t.Fatalf("invalid postgres connection lifetime: %s", postgresConnMaxLifetime)
    }
}
```

Run:

```text
go test ./internal/db -run TestPoolSettingsHaveFiniteLifetime -count=1
```

Expected: FAIL because the constant/configuration does not exist or is zero.

- [ ] **Step 2: Implement minimal configuration**

Define `const postgresConnMaxLifetime = 30 * time.Minute` near the existing pool settings and call:

```go
db.SetConnMaxLifetime(postgresConnMaxLifetime)
```

Do not increase `MaxOpenConns` beyond the current bounded formula without measured evidence.

- [ ] **Step 3: Run the focused test**

```text
go test ./internal/db -run TestPoolSettingsHaveFiniteLifetime -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit**

```text
git add internal/db/provider.go internal/db/provider_test.go
git commit -m "perf(db): recycle postgres connections safely"
```

---

### Task 3: Add PostgreSQL search extension and targeted indexes

**Files:**
- Create: `internal/db/migrations/039_search_indexes.sql`
- Test: `internal/db/search_indexes_test.go`

**Interfaces:**
- Migration `039_search_indexes.sql` is canonical, embedded automatically by `MigrationsFS`, transactional, and idempotent.
- It creates `pg_trgm` and GIN indexes for existing substring-search columns only: `passwords.url`, `passwords.username`, `passwords.password_value`, `cookies.domain`, `cookies.name`, `cookies.value`, `cards.holder`, `cards.number`, `wallets.name`, and `wallets.path`.
- Index names must be exact and stable: `idx_passwords_search_trgm`, `idx_cookies_search_trgm`, `idx_cards_search_trgm`, `idx_wallets_search_trgm`.

- [ ] **Step 1: Write the failing schema test**

The test must use `TEST_DATABASE_URL` through `testutil.OpenTestDB`, run migrations, then query `pg_extension` and `pg_indexes`; assert extension `pg_trgm` and all four exact index names exist.

Run:

```text
TEST_DATABASE_URL='postgres://...' go test ./internal/db -run TestSearchIndexes -count=1
```

Expected: FAIL because migration 039/indexes do not exist.

- [ ] **Step 2: Implement migration**

Use PostgreSQL-native, idempotent SQL:

```sql
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE INDEX IF NOT EXISTS idx_passwords_search_trgm ON passwords USING gin ((coalesce(url, '') || ' ' || coalesce(username, '') || ' ' || coalesce(password_value, '')) gin_trgm_ops);
```

Use equivalent grouped expressions for cookies, cards, and wallets. Keep expressions aligned with actual search predicates; never interpolate request data. If existing predicates cannot use grouped expression indexes, create separate column indexes instead and update the exact test contract accordingly.

- [ ] **Step 3: Run focused schema test**

```text
TEST_DATABASE_URL='postgres://...' go test ./internal/db -run TestSearchIndexes -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit**

```text
git add internal/db/migrations/039_search_indexes.sql internal/db/search_indexes_test.go

git commit -m "perf(db): add postgres trigram search indexes"
```

---

### Task 4: Fix remaining PostgreSQL-incompatible SQL

**Files:**
- Modify: `internal/api/stats.go`, `internal/api/stats_public.go`, and any exact files found by the scoped search below
- Tests: nearest existing API tests covering stats

**Interfaces:**
- Preserve JSON response shapes and query semantics.
- PostgreSQL date arithmetic must use `CURRENT_TIMESTAMP - INTERVAL 'N days'`; grouping by day must use `created_at::date`.

- [ ] **Step 1: Write a failing regression test**

Add a stats integration case that inserts a session with `CURRENT_TIMESTAMP - INTERVAL '1 day'`, calls the stats handler against a PostgreSQL test schema, and asserts HTTP 200 plus a timeline response.

Run:

```text
TEST_DATABASE_URL='postgres://...' go test ./internal/api -run 'Test.*Stats' -count=1
```

Expected: FAIL if any SQLite `date()` expression remains.

- [ ] **Step 2: Locate and replace only SQLite expressions**

Run:

```text
grep -RInE "date\('now'|datetime\('now'" internal/api internal/services internal/middleware
```

Replace each runtime occurrence with PostgreSQL-native expressions; do not alter unrelated frontend strings or comments.

- [ ] **Step 3: Run focused stats tests**

```text
TEST_DATABASE_URL='postgres://...' go test ./internal/api -run 'Test.*Stats' -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit**

```text
git add internal/api/stats.go internal/api/stats_public.go internal/api/*stats*test.go
git commit -m "fix(api): use postgres date arithmetic"
```

---

### Task 5: Add deterministic query-plan verification

**Files:**
- Create: `internal/db/query_plan_test.go`
- Modify: `internal/db/testutil` only if a reusable plan helper is necessary

**Interfaces:**
- Test helper executes `EXPLAIN (FORMAT JSON)` through PostgreSQL and decodes the JSON plan.
- Tests must insert enough deterministic rows to make the trigram index eligible, run `ANALYZE`, and assert the plan contains one of the exact stable trigram indexes. If the planner chooses a sequential scan for a tiny fixture, the test must assert index existence and use a larger fixture rather than forcing planner GUCs in production.

- [ ] **Step 1: Write failing plan test**

Create `TestSearchQueryUsesTrigramIndex` with deterministic fixtures and assertion that the decoded plan contains `idx_passwords_search_trgm`.

Run:

```text
TEST_DATABASE_URL='postgres://...' go test ./internal/db -run TestSearchQueryUsesTrigramIndex -count=1
```

Expected: FAIL before migration/index support.

- [ ] **Step 2: Implement test-only plan traversal**

Traverse `Plan`, `Plans`, and `Index Name` fields recursively. Do not add planner hints or disable sequential scans in application code.

- [ ] **Step 3: Run focused plan test and migration test**

```text
TEST_DATABASE_URL='postgres://...' go test ./internal/db -run 'Test(SearchQueryUsesTrigramIndex|SearchIndexes)' -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit**

```text
git add internal/db/query_plan_test.go
git commit -m "test(db): verify postgres search query plans"
```

---

### Task 6: Run full deterministic verification and backup/restore

**Files:**
- Inspect: all current changes, `.github/workflows/backend.yml`, Compose files
- Artifacts: external temporary dump and manifest only; never commit them

**Interfaces:**
- No source changes unless a failing verification reveals a real defect; every fix returns to the relevant TDD task.

- [ ] **Step 1: Run full backend checks against PostgreSQL**

```text
TEST_DATABASE_URL='postgres://...' go test -count=1 ./internal/...
TEST_DATABASE_URL='postgres://...' go test -race ./internal/...
go vet ./...
go build ./...
```

Expected: all pass. Record exact output outside the repository if it contains environment details.

- [ ] **Step 2: Build and smoke Docker**

```text
docker compose build --no-cache panel
docker compose up -d postgres panel
docker compose ps
curl -fsS http://localhost:8080/health
```

Expected: build succeeds, PostgreSQL/panel healthy, `/health` returns 200. Exercise login, session ingestion fixture, search, build creation, file download, tenant isolation, and websocket notification with existing safe fixtures; do not use real credentials/data.

- [ ] **Step 3: Verify backup and restore**

```text
docker compose --profile backup run --rm backup
```

For a true restore check, create a disposable PostgreSQL 16 container on the Compose network, restore the newest custom dump with `pg_restore --clean --if-exists`, run schema/table/count/checksum checks, then remove only that disposable container. Never overwrite `pgdata` or the only dump.

- [ ] **Step 4: Verify migration idempotence and drift**

Run the migration test twice against isolated schemas; assert `_migrations` count/hash stability. Modify only a disposable copied migration in a test harness and assert `VerifySchema` rejects hash drift; never edit production migration history.

- [ ] **Step 5: Commit verification-only source fixes if required**

```text
git status --short
git diff --check
```

Do not stage unrelated C-code changes, legacy databases, secrets, cookies, dumps, or generated frontend output.

---

### Task 7: GitHub integration gate

**Files:**
- Inspect: `.git`, `git remote -v`, `gh auth status`
- Modify: no files unless CI needs a narrowly scoped correction

**Interfaces:**
- Commit/push/PR only with verified repository identity and authenticated credentials.

- [ ] **Step 1: Inspect GitHub availability**

```text
git rev-parse --show-toplevel
git remote -v
gh auth status
```

Expected: repository root and authenticated account. If `.git` is absent or `gh` unauthenticated, stop GitHub actions and report exact blocker; do not fabricate a PR.

- [ ] **Step 2: Review diff boundaries**

```text
git diff --check
git status --short
```

Explicitly exclude unrelated parent-repo C changes, `cookies.txt`, `.jwt_secret`, `data/mirage.db`, dumps, and generated/private files.

- [ ] **Step 3: Create commit, push, and PR only if gate passes**

```text
git checkout -b perf/postgres-verification
git add <only panel PostgreSQL files>
git commit -m "perf: verify and optimize postgres panel path"
git push -u origin perf/postgres-verification
gh pr create --title "perf: verify and optimize PostgreSQL panel" --body-file <review-notes-file>
```

Review CI status and PR checks; never include passwords or private fixture data in the PR body.
