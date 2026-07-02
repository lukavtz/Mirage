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

## Phase 2: Sessions & Data (Sprint 2, ~3 дня)

- [ ] `GET /api/sessions` — пагинированный список
- [ ] TanStack Table — сортировка, фильтрация, column toggle
- [ ] Row click → SessionDetail
- [ ] `GET /api/sessions/{id}` — полный детал
- [ ] Tabbed view: Passwords, Cookies, Cards, Wallets, Files, System Info
- [ ] Password reveal toggle (👁 show/hide)
- [ ] Country flag badges in table
- [ ] Bulk delete sessions
- [ ] OS / browser icons

**Done →** Оператор просматривает и фильтрует тысячи сессий без лагов.

---

## Phase 3: Search (Sprint 3, ~1 день)

- [ ] `GET /api/search` — full-text across passwords, cookies, cards, sessions
- [ ] Search page UI
- [ ] Type filter dropdown (passwords/cookies/cards/all)
- [ ] Highlight matched fields
- [ ] Click result → SessionDetail
- [ ] Keyboard shortcuts (`/` to focus search)

**Done →** Мгновенный поиск по всей базе украденных данных.

---

## Phase 4: Log Ingestion (Sprint 4, ~2 дня)

- [ ] `POST /api/log` — multipart ZIP + metadata
- [ ] `POST /api/log/chunk` + `/api/log/complete`
- [ ] LogProcessor — ZIP parse + DB insert (transaction)
- [ ] Path traversal protection
- [ ] Raw ZIP saving to `/data/logs/`
- [ ] `POST /api/log/ssp` — ServerSideDecrypt
- [ ] ServerSideDecrypt — Chromium AES-GCM (v10/v11)
- [ ] ServerSideDecrypt — Gecko NSS decrypt
- [ ] WebSocket broadcast on new log
- [ ] Payload size limit middleware (100 MB)

**Done →** Панель принимает логи от стилера, обрабатывает их и сохраняет.

---

## Phase 5: Build & Telegram (Sprint 5, ~2 дня)

### Build Service
- [ ] `POST /api/build` — сборка стилера
- [ ] MIRAGECFG search in PE `.rdata`
- [ ] AES-GCM config encryption
- [ ] MirageDecryptor.dll overlay append
- [ ] `GET /api/build/{id}/download`
- [ ] Build tag + build history table
- [ ] Build page UI (form + config fields)
- [ ] Last build display with download

### Telegram Proxy
- [ ] Forward logs to Telegram Bot API
- [ ] Caption formatting (country, counts, IP)
- [ ] Token validation (test button)
- [ ] Retry logic (3 attempts)

**Done →** Оператор собирает стилер прямо из веб-панели и получает логи в Telegram.

---

## Phase 6: SSP & Enterprise (Sprint 6, ~3 дня)

### Server-Side Processing
- [ ] Full Chromium profile decryption (Login Data, Cookies, Web Data, History)
- [ ] Full Gecko profile decryption (logins.json + key4.db)
- [ ] Credit card + CVC extraction from Web Data
- [ ] OAuth token extraction (Google, Outlook)
- [ ] Temp file cleanup after SSP

### Notes / Comments
- [ ] Notes table (session_id, text, created_by, created_at)
- [ ] Add note to session UI
- [ ] Mark session as checked/flagged

### Export
- [ ] Export single session as JSON/HTML
- [ ] Bulk export selected sessions as ZIP
- [ ] Export all by filter (by country, date range)

**Done →** Полноценная enterprise-панель с SSP.

---

## Phase 7: Hardening & Polish (Sprint 7, ~2 дня)

- [ ] PostgreSQL support (через `database/sql` interface)
- [ ] HTTPS / TLS via embedded autocert (Let's Encrypt)
- [ ] Rate limit settings page (configurable per-tier)
- [ ] Audit log (who did what, when)
- [ ] Session → ban from session page
- [ ] Dark/light theme toggle
- [ ] i18n (EN + RU)
- [ ] Keyboard shortcuts (full list)
- [ ] 404 page, error boundaries
- [ ] Loading skeletons everywhere
- [ ] Empty states (no data yet)

**Done →** Панель готова к продакшену.

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
| 2 | Sessions & Data (table, detail, tabs) | 3 | ⬜ |
| 3 | Search (full-text across all data) | 1 | ⬜ |
| 4 | Log Ingestion (multipart, chunked, SSP) | 2 | ⬜ |
| 5 | Build & Telegram | 2 | ⬜ |
| 6 | SSP & Enterprise (export, notes) | 3 | ⬜ |
| 7 | Hardening & Polish | 2 | ⬜ |
| 8 | Multi-User & Licensing | 3 | ⬜ |
| 9 | Cookie Restore | 2 | ⬜ |
| 10 | Commercial & Ops | 2 | ⬜ |
| **Total** | | **~26 дней** | **2/11 ✅** |

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
