# Panel Hardening Verification — 2026-08-07

Commit pushed: `9d9689e fix(panel): harden reset flow and release verification`

## Passed

- Frontend: `52` Vitest files, `363` tests passed; `npm run build` passed.
- Docker: production image built as `mirage-panel-final`; Compose backup profile config validated with explicit secrets.
- Backend focused PostgreSQL API regression: build list and reset-token tests passed in the existing Compose PostgreSQL network.
- Focused race coverage passed with CGO enabled: reset-token and build-list API tests.
- `git diff --check` passed for committed panel files.

## CI / repository evidence

- Existing GitHub PR #5 checks were inspected. The historical race failure used the pre-fix command and timed out at 10 minutes; checked-in CI now uses `go test -race -p 1 -timeout=30m -count=1 ./internal/...`.
- The C Stealer workflow remains unrelated to panel changes and still fails on the existing PR.
- Unrelated working-tree changes under `Makefile`, `include/`, `src/`, `tools/`, and new generator artifacts were not staged or modified by this release commit.

## Remaining risk

A full backend race run was not re-run after the CI timeout change; the focused race slice passed. The branch has no new PR; changes were pushed to `feat/data-tabs` for the existing PR context.
