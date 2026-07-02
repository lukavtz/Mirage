# Eidos Web Panel — Roadmap

**Статус:** Планирование / Sprint 0  
**Репозиторий:** `eidos-panel/` (будет создан)  
**Стек:** Go 1.24 + React 19 + shadcn/ui + SQLite | [см. STACK.md](./STACK.md)

---

## Legend

- [x] Done
- [ ] In progress / planned
- [~] Blocked / needs dependency
- [- ] Not planned yet

---

## Phase 0: Foundation (Sprint 0, ~3 дня)

**Цель:** Рабочий скелет — Go сервер, React скелет, авторизация, SQLite

### Backend (Go)
- [ ] `go mod init` + chi router + middleware stack
- [ ] SQLite init + миграции (users, sessions, etc.)
- [ ] JWT auth (login/logout/refresh)
- [ ] Rate limiting middleware
- [ ] Ban middleware (IP check)
- [ ] Settings table + API
- [ ] `//go:embed` статики фронтенда
- [ ] Makefile + live-reload (air)

### Frontend (React)
- [ ] Vite + shadcn/ui + Tailwind init
- [ ] Dark theme + design system tokens
- [ ] Login page
- [ ] Auth context + protected routes
- [ ] Layout shell (sidebar + topbar + content)
- [ ] Sidebar navigation with collapse
- [ ] API client (`lib/api.ts`)
- [ ] WebSocket client (`lib/ws.ts`)

**Done →** Go сервер отдаёт React SPA, работает логин, пустой Dashboard.

---

## Phase 1: Dashboard (Sprint 1, ~3 дня)

- [ ] `GET /api/stats` — все метрики
- [ ] WebSocket hub — broadcast stats updates
- [ ] Stat cards (4 шт: Sessions, Passwords, Cookies, Wallets)
- [ ] Timeline chart (30 days, Recharts AreaChart)
- [ ] Browser distribution pie/donut chart
- [ ] Geo distribution bar chart (флаги + counts)
- [ ] Top 10 domains table
- [ ] Auto-refresh через WS + fallback polling 10s
- [ ] Connection status indicator (🟢 / 🟡 / 🔴)

**Done →** Оператор видит полную картину на дашборде с live-обновлением.

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

| Phase | Что | Дней | Спринт |
|-------|-----|------|--------|
| 0 | Foundation (Go server + React shell + auth) | 3 | Sprint 0 |
| 1 | Dashboard (stats, charts, live updates) | 3 | Sprint 1 |
| 2 | Sessions & Data (table, detail, tabs) | 3 | Sprint 2 |
| 3 | Search (full-text across all data) | 1 | Sprint 3 |
| 4 | Log Ingestion (multipart, chunked, SSP) | 2 | Sprint 4 |
| 5 | Build & Telegram | 2 | Sprint 5 |
| 6 | SSP & Enterprise (export, notes) | 3 | Sprint 6 |
| 7 | Hardening & Polish | 2 | Sprint 7 |
| 8 | Multi-User & Licensing | 3 | Sprint 8 |
| 9 | Cookie Restore | 2 | Sprint 9 |
| 10 | Commercial & Ops | 2 | Sprint 10 |
| **Total** | | **~26 дней** | **11 спринтов** |

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
