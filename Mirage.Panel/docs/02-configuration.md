# Configuration

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 8080 | HTTP server port |
| DB_PATH | data/mirage.db | SQLite database path |
| JWT_SECRET | auto | JWT signing secret |
| ALLOWED_ORIGINS | http://localhost:5173 | CORS origins |

## Settings

- **Rate Limit**: Maximum API requests per minute
- **Telegram**: Bot notifications integration
- **Public Stats**: Enable public statistics page

## Database

SQLite with WAL mode. Migrations run automatically on startup.
