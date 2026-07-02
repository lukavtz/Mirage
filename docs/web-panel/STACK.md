# Eidos Web Panel — Tech Stack

## Decision Matrix

| Criteria | **Go + React** | Next.js (fullstack) | Python FastAPI + React |
|----------|---------------|---------------------|----------------------|
| Single binary | ✅ `//go:embed` | ❌ Needs Node.js | ❌ Needs Python |
| Cross-compile | ✅ `GOOS=windows go build` | ❌ | ❌ |
| Concurrency | ✅ Goroutines native | ⚠️ Event loop | ❌ GIL |
| Embed UI | ✅ stdlib | ❌ | ❌ |
| Binary size | ~15 MB | N/A | N/A |
| Ecosystem Maturity | ✅ Go stdlib + chi | ✅ React ecosystem | ⚠️ |
| C2 panels using it | ByteCode, ShardC2, Pulse-C2 | — | — |

**Verdict:** Go + React. Single static binary, zero runtime deps, embed UI at compile time — идеально для C2 инфраструктуры.

---

## Stack Components

### Backend — Go

```
Installed:   Go 1.25.6 (go version)
Latest:      Go 1.26.0 (context7)

Router:      chi/v5 v5.3.0 (go list)
Database:    SQLite via modernc.org/sqlite v1.8.3 (pure Go, no CGO)
Auth:        JWT (golang-jwt/jwt/v5 v5.3.1)
WebSocket:   gorilla/websocket v1.5.3
Embed:       //go:embed (stdlib) — фронтенд в бинарнике
Crypto:      standard library AES-GCM, ChaCha20, BCrypt, SHA-256
Logging:     slog (stdlib)
Config:      YAML via gopkg.in/yaml.v3
HTTP client: net/http (stdlib)
```

**Почему chi, а не gin/fiber:**
- chi совместим с `net/http` — middleware из стандартной библиотеки работают напрямую
- Нет магии, нет reflection-based binding
- Легче поддерживать и заменять

### Frontend — React + Vite + TypeScript

```
Installed:   Node.js 24.14.1, npm 11.11.0
Framework:   React 19 (latest: 19.2.7)
Build:       Vite 8 (latest: 8.0.10)
UI Library:  shadcn/ui (CLI 3.5.0, Radix UI primitives)
Tables:      TanStack Table v8 (latest v8, react-table)
Charts:      Recharts 3 (latest: 3.3.0)
Forms:       react-hook-form + zod
Icons:       lucide-react (thin line icons)
Theming:     next-themes (dark/light)
HTTP:        fetch + @tanstack/react-query
WebSocket:   native WebSocket + react-use-websocket
Maps:        react-simple-maps (country heatmap)
Date:        date-fns
```

**Почему shadcn/ui:**
- Dark theme из коробки
- Компоненты высшего качества (Data Table с сортировкой/фильтрацией/пагинацией)
- Copy-paste подход — весь код твой, никаких зависимостей
- Стилизация через Tailwind CSS — никаких CSS-in-JS runtime

### Dev Tools

```
Go:
  - air (hot reload backend)
  - golangci-lint
  - go test -race

Frontend:
  - Vite HMR (hot reload)
  - TypeScript strict mode
  - ESLint + Prettier
  - Vitest (unit tests)
  - Playwright (e2e tests)

Build:
  - make (или Taskfile)
  - Docker (опционально)
  - GitHub Actions (CI)
```

---

## Project Structure

```
eidos-panel/
├── cmd/
│   └── panel/
│       └── main.go              # Entry point
│
├── internal/
│   ├── api/
│   │   ├── router.go            # chi router setup
│   │   ├── middleware.go        # Auth, rate limit, CORS, logging
│   │   ├── auth.go              # POST /api/auth/login
│   │   ├── stats.go             # GET /api/stats
│   │   ├── sessions.go          # CRUD sessions
│   │   ├── search.go            # GET /api/search
│   │   ├── logs.go              # POST /api/log, chunked
│   │   ├── build.go             # POST /api/build, download
│   │   ├── bans.go              # CRUD bans
│   │   ├── settings.go          # GET/PUT /api/settings
│   │   └── ssp.go               # POST /api/log/ssp
│   │
│   ├── auth/
│   │   ├── jwt.go               # JWT generation/validation
│   │   └── password.go          # BCrypt hash/verify
│   │
│   ├── db/
│   │   ├── sqlite.go            # SQLite connection + migrations
│   │   ├── migrations/          # .sql migration files
│   │   └── models.go            # Go structs (Session, Password, Cookie, etc.)
│   │
│   ├── services/
│   │   ├── log_processor.go     # ZIP parsing + DB insert
│   │   ├── log_processor_test.go
│   │   ├── server_side_decrypt.go  # Browser DB decrypt
│   │   ├── build_service.go     # PE patching
│   │   ├── telegram_proxy.go    # Forward to TG
│   │   └── country_lookup.go    # IP → country code
│   │
│   └── ws/
│       ├── hub.go               # WebSocket connection hub
│       └── client.go            # Per-connection handler
│
├── frontend/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Login.tsx
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Sessions.tsx
│   │   │   ├── SessionDetail.tsx
│   │   │   ├── Build.tsx
│   │   │   ├── Search.tsx
│   │   │   └── Settings.tsx
│   │   ├── components/
│   │   │   ├── ui/              # shadcn/ui
│   │   │   ├── layout/          # Sidebar, Topbar, Shell
│   │   │   └── charts/          # GeoMap, Timeline, Pie
│   │   ├── lib/
│   │   │   ├── api.ts           # API client
│   │   │   └── ws.ts            # WebSocket client
│   │   └── types/
│   │       └── index.ts         # TypeScript types
│   ├── package.json
│   └── vite.config.ts
│
├── data/                        # Runtime data dir
│   ├── mirage.db                # SQLite database
│   └── logs/                    # Raw ZIP archives
│
├── go.mod
├── Makefile
└── Dockerfile
```

---

## Build & Run

```bash
# Dev — backend (hot reload)
cd backend && air

# Dev — frontend (HMR on :5173, proxy to :8080)
cd frontend && npm run dev

# Production — single binary
cd frontend && npm run build    # → dist/
cd ../backend && go build -o eidos-panel ./cmd/panel
# → eidos-panel (~15 MB, contains all frontend assets)

# Run
./eidos-panel --port 8080 --db ./data/mirage.db
```

## Deployment

```dockerfile
FROM alpine:3.21
COPY eidos-panel /usr/bin/
COPY data/ /data/
EXPOSE 8080
CMD ["eidos-panel", "--port", "8080", "--db", "/data/mirage.db"]
```

Behind nginx/Caddy for TLS termination.
