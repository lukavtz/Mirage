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

## Fresh verification — 2026-08-07

- Full backend PostgreSQL suite passed in the Compose PostgreSQL network: `internal/api`, `auth`, `builder`, `db`, `middleware`, `services`, `services/bot`, and `ws`.
- Full backend race suite passed with `CGO_ENABLED=1`, `-race -p 1 -timeout=30m`: same package set.
- Frontend passed again: `52` files and `363` tests; production build completed.
- Fresh Docker image `mirage-panel-fresh` built successfully.
- API smoke: `/health`, `/api/csrf`, and `/api/pricing` returned HTTP 200.
- Backup profile smoke completed with `Backup and restore check complete`.
- Current PR #5 status: Backend, Frontend, and Docker checks SUCCESS; unrelated C Stealer `build` check FAILURE; PR remains OPEN.

## Remaining risk

The C Stealer workflow is unrelated to panel changes and remains failing. Existing unrelated parent-repository changes remain unstaged and were preserved.
