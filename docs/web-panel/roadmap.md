# Eidos Web Panel — Roadmap

**Статус:** Phase 1 ✅  
**Репозиторий:** `Mirage.Panel/`  
**Стек:** Go 1.25 + React 19 + shadcn/ui + SQLite | [см. STACK.md](./STACK.md)

---

## Legend

- [x] Done
- [ ] In progress / planned
- [~] Blocked / needs dependency
- [- ] Not planned yet

---

## Phase 0: Foundation ✅

**Цель:** Рабочий скелет — Go сервер, React скелет, авторизация, SQLite

### Backend (Go)
- [x] `go mod init` + chi router + middleware stack
- [x] SQLite init + миграции (users, sessions, etc.)
- [x] JWT auth (login/logout/refresh)
- [x] Rate limiting middleware
- [x] Ban middleware (IP check)
- [x] Settings table + API
- [x] `//go:embed` статики фронтенда
- [x] Makefile + live-reload (air)

### Frontend (React)
- [x] Vite + shadcn/ui + Tailwind init
- [x] Dark theme + design system tokens
- [x] Login page
- [x] Auth context + protected routes
- [x] Layout shell (sidebar + topbar + content)
- [x] Sidebar navigation with collapse
- [x] API client (`lib/api.ts`)
- [x] WebSocket client (`lib/ws.ts`)

---

## Phase 1: Dashboard ✅

- [x] `GET /api/stats` — все метрики
- [x] WebSocket hub — broadcast stats updates
- [x] Stat cards (4 шт: Sessions, Passwords, Cookies, Wallets)
- [x] Timeline chart (30 days, Recharts AreaChart)
- [x] Browser distribution pie/donut chart
- [x] Geo distribution bar chart (флаги + counts)
- [x] Top 10 domains table
- [x] Auto-refresh через WS + fallback polling 10s
- [x] Connection status indicator (🟢 / 🟡 / 🔴)

---

## Phase 2: Sessions & Data ✅

- [x] `GET /api/sessions` — пагинированный список
- [x] TanStack Table — сортировка, фильтрация, column toggle
- [x] Row click → SessionDetail
- [x] `GET /api/sessions/{id}` — полный детал
- [x] Tabbed view: Passwords, Cookies, Cards, Wallets, Files, System Info
- [x] Password reveal toggle (👁 show/hide)
- [x] Country flag badges in table
- [x] Bulk delete sessions
- [x] OS / browser icons

---

## Phase 3: Search ✅

- [x] `GET /api/search` — full-text across passwords, cookies, cards, sessions
- [x] Search page UI
- [x] Type filter dropdown (passwords/cookies/cards/all)
- [x] Highlight matched fields
- [x] Click result → SessionDetail
- [x] Keyboard shortcuts (`/` to focus search)

---

## Phase 4: Log Ingestion ✅

- [x] `POST /api/log` — multipart ZIP + metadata
- [x] `POST /api/log/chunk` + `/api/log/complete`
- [x] LogProcessor — ZIP parse + DB insert (transaction)
- [x] Path traversal protection
- [x] Raw ZIP saving to `/data/logs/`
- [x] `POST /api/log/ssp` — ServerSideDecrypt
- [x] ServerSideDecrypt — Chromium AES-GCM (v10/v11)
- [x] ServerSideDecrypt — Gecko NSS decrypt
- [x] WebSocket broadcast on new log
- [x] Payload size limit middleware (100 MB)

---

## Phase 5: Build & Telegram ✅

### Build Service
- [x] `POST /api/build` — сборка стилера
- [x] MIRAGECFG search in PE `.rdata`
- [x] AES-GCM config encryption
- [x] MirageDecryptor.dll overlay append
- [x] `GET /api/build/{id}/download`
- [x] Build tag + build history table
- [x] Build page UI (form + config fields)
- [x] Last build display with download

### Telegram Proxy
- [x] Forward logs to Telegram Bot API
- [x] Caption formatting (country, counts, IP)
- [x] Token validation (test button)
- [x] Retry logic (3 attempts)

---

## Phase 6: SSP & Enterprise ✅

### Server-Side Processing
- [x] Full Chromium profile decryption (Login Data, Cookies, Web Data, History)
- [x] Full Gecko profile decryption (logins.json + key4.db)
- [x] Credit card + CVC extraction from Web Data
- [x] Temp file cleanup after SSP

### Notes / Comments
- [x] Notes table (session_id, text, created_by, created_at)
- [x] Add note to session UI
- [x] Mark session as checked/flagged

### Export
- [x] Export single session as JSON/HTML
- [x] Bulk export selected sessions as ZIP

---

## Phase 7: Hardening & Polish ✅

- [x] PostgreSQL support (через `database/sql` interface)
- [x] HTTPS / TLS (self-signed + autocert config)
- [x] Rate limit settings page (configurable per-tier)
- [x] Audit log (who did what, when)
- [x] Session → ban from session page
- [x] Dark/light theme toggle
- [x] i18n (EN + RU)
- [x] Loading skeletons everywhere
- [x] Empty states (no data yet)

---

## Phase 8: Multi-User & Licensing (Sprint 8, ~3 дня)

- [ ] Users/Roles table (admin, worker, viewer)
- [ ] Invite codes with role + expiration
- [ ] Session lock (worker checks out → others hidden)
- [ ] Activity log per worker
- [ ] License key generation
- [ ] License expiry enforcement
- [ ] Tier limits (Starter: 1 TG bot / Pro: 7 / Team: 15)
- [ ] Subscription management UI
- [ ] Public statistics page (optional, token-gated)

**Done →** Multi-user C2 панель с лицензированием (готово к продажам).

---

## Phase 9: Cookie Restore (Sprint 9, ~2 дня)

- [ ] Google Refresh Token → Access Token exchange
- [ ] Cookie import in browser-compatible format
- [ ] SOCKS5 proxy integration for restore
- [ ] Proxy rotation (list of proxies → rotate on each restore)
- [ ] Restore history per session
- [ ] One-click cookie restore from session detail

**Done →** Функционал cookie restore — киллер-фича для Pro/Team тарифов.

---

## Phase 10: Commercial & Ops (Sprint 10, ~2 дня)

- [ ] Telemetry (panel version, sessions count — для автора)
- [ ] Remote update check
- [ ] Backup/restore database
- [ ] Dockerfile + docker-compose
- [ ] GitHub CI (lint, test, build)
- [ ] README with screenshots
- [ ] Landing page API docs (swagger)

**Done →** Коммерческий запуск.

---

## Phases Summary

| Phase | Что | Дней | Статус |
|-------|-----|------|--------|
| 0 | Foundation (Go server + React shell + auth) | 3 | ✅ Done |
| 1 | Dashboard (stats, charts, live updates) | 3 | ✅ Done |
| 2 | Sessions & Data (table, detail, tabs) | 3 | ✅ Done |
| 3 | Search (full-text across all data) | 1 | ✅ Done |
| 4 | Log Ingestion (multipart, chunked, SSP) | 3 | ✅ Done |
| 5 | Build & Telegram | 2 | ✅ Done |
| 6 | SSP & Enterprise (export, notes) | 3 | ✅ Done |
| 7 | Hardening & Polish | 2 | ✅ Done |
| 8 | Multi-User & Licensing | 3 | ⬜ |
| 9 | Cookie Restore | 2 | ⬜ |
| 10 | Commercial & Ops | 2 | ⬜ |
| **Total** | | **~26 дней** | **8/11 ✅** |

---

## Quick Start (после Phase 0)

```bash
# Clone
git clone https://github.com/your/eidos-panel
cd eidos-panel

# Backend
cd backend
go run ./cmd/panel --port 8080

# Frontend (dev mode)
cd frontend
npm install
npm run dev

# Build production single binary
cd frontend && npm run build
cd ../backend && go build -o eidos-panel ./cmd/panel
./eidos-panel --port 8080
```
