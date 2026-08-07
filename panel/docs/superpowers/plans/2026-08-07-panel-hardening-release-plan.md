# Panel Hardening and Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Harden the PostgreSQL-only Mirage panel, make production secrets/backups explicit, verify the complete stack, and publish reviewable GitHub commits without including unrelated repository changes.

**Architecture:** Keep the existing Go `database/sql` + pgx/PostgreSQL design and existing API shapes. Fix security behavior at shared middleware/ownership/transport boundaries, use transactions for password-reset invalidation, and make Docker configuration fail closed for production. Backups remain operator-controlled; off-host delivery is an explicit S3-compatible target rather than an implicit upload.

**Tech Stack:** Go 1.25, Chi, gorilla/websocket, pgx/v5, PostgreSQL 16, Docker Compose, React/Vite, GitHub CLI.

## Global Constraints

- PostgreSQL remains the only panel runtime database; do not add SQLite compatibility.
- No user-controlled header is trusted for security identity; proxy trust is explicit and disabled by default.
- Every behavioral fix gets a failing regression test before production code.
- Preserve API response shapes and unrelated working-tree changes.
- Never commit `.env`, credentials, dumps, generated private data, or cookies.
- Backup off-host delivery must fail closed when configured and must not log credentials.
- Production deployment requires externally supplied secrets and TLS certificates; local development may use explicit opt-in settings only.

---

### Task 1: Security regression tests and boundary review

**Files:**
- Test: `internal/middleware/ratelimit_test.go`, `internal/ws/*_test.go`, `internal/api/*_test.go`
- Inspect: `internal/middleware/ratelimit.go`, `internal/middleware/realip.go`, `internal/ws/hub.go`, `internal/api/helpers.go`, `internal/api/auth.go`

**Interfaces:**
- Direct client identity is derived from `RemoteAddr` unless an explicit trusted-proxy configuration is added.
- WebSocket unregister and slow-client eviction are idempotent and remove the client from every channel before closing its send path.
- Ownership helpers return false when claims are missing.
- Password reset is atomic: token consumption and session invalidation either both commit or neither does.

- [ ] Write focused failing tests for spoofed XFF, WebSocket slow-client cleanup, missing-claims ownership, and reset DB failure.
- [ ] Run each focused test and confirm the expected failure.
- [ ] Record exact affected callsites and no unrelated scope.

### Task 2: Fix IP extraction and WebSocket lifecycle

**Files:**
- Modify: `internal/middleware/ratelimit.go`, `internal/middleware/ban.go`, `internal/api/auth.go`, `internal/ws/hub.go`, `internal/ws/client.go`
- Test: corresponding focused regression tests

**Interfaces:**
- `ExtractIP(*http.Request) string` must not use `X-Forwarded-For` or `X-Real-IP` by default.
- WebSocket hub cleanup must delete channel membership before closing, and repeated unregister must be harmless.

- [ ] Implement the smallest fail-closed IP change and idempotent hub cleanup.
- [ ] Run focused middleware/WebSocket tests.
- [ ] Run package tests and race tests for middleware and ws.

### Task 3: Fix reset/session error handling and ownership fail-open

**Files:**
- Modify: `internal/api/auth.go`, `internal/api/helpers.go`
- Test: auth and helper regression tests

**Interfaces:**
- Login and 2FA login return an error instead of issuing a JWT when auth-session persistence fails.
- Password reset uses one transaction to mark the reset token used and invalidate sessions; transaction errors return a generic server error and do not claim success.
- `sessionOwnedBy` and `buildOwnedBy` deny access when claims are absent.
- Existing authorized behavior and JSON response shapes remain unchanged.

- [ ] Implement transaction/error handling after the failing tests exist.
- [ ] Run focused auth/ownership tests.
- [ ] Run package tests and race tests.

### Task 4: Production secrets, TLS, and backup policy

**Files:**
- Modify: `.env.example`, `.gitignore`, `docker-compose.yml`, `Dockerfile`, `cmd/panel/main.go`, `tools/postgresql-cutover/USAGE.md`
- Add only if needed: `backup/` operator scripts/configuration already required by Compose

**Interfaces:**
- `.env.example` contains placeholders/instructions only; no usable test secret.
- Compose requires `DATABASE_URL`, `DB_PASSWORD`, `JWT_SECRET`, and production TLS inputs when `APP_ENV=production`.
- TLS uses mounted certificate/key files in production; self-signed TLS is local-only and explicit.
- Backup retention is bounded by an explicit `BACKUP_RETENTION_DAYS`; off-host upload is optional but, when configured, requires an S3-compatible endpoint/bucket/credentials and reports failure.

- [ ] Add configuration tests for missing production secrets/TLS and backup retention validation.
- [ ] Verify tests fail before implementation.
- [ ] Implement minimal environment/configuration changes without introducing a cloud SDK; use the existing PostgreSQL image tooling and an operator-provided uploader command/target.
- [ ] Run config tests and `docker compose config` with safe throwaway environment values.

### Task 5: Full deterministic verification and Docker smoke test

**Files:**
- Inspect all panel source and CI files; modify only verified failures.

- [ ] Run `TEST_DATABASE_URL=... go test -count=1 ./internal/...`.
- [ ] Run `TEST_DATABASE_URL=... go test -race ./internal/...`.
- [ ] Run `go vet ./...` and `go build ./...`.
- [ ] Run frontend build and Vitest.
- [ ] Build Docker image with retry-safe network settings.
- [ ] Start PostgreSQL and panel; verify health, login, protected API, ingestion, search, export/download, and WebSocket behavior with disposable fixtures.
- [ ] Run backup and restore verification; verify retention/off-host configuration without uploading real data.
- [ ] Stop all services and record exact evidence.

### Task 6: Reviewable GitHub release

**Files:**
- Only verified panel changes; never stage unrelated parent-repository changes.

- [ ] Inspect repository root, remotes, branch, status, and diff by scope.
- [ ] Split changes into hardening, operations/config, and tests/docs commits.
- [ ] Run `git diff --check` and inspect staged diffs.
- [ ] Authenticate `gh` interactively if credentials are unavailable; never print tokens.
- [ ] Push a named branch and create a PR with test evidence and explicit remaining risks.
- [ ] Verify PR metadata/checks and report URLs.
