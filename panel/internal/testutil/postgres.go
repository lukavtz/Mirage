package testutil

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
	"zialfi-panel/internal/db"
)

// GetTestDB returns a test database connection. When TEST_DATABASE_URL is set,
// an isolated PostgreSQL schema is used. Otherwise an in-memory SQLite database
// is created with the tables needed by middleware tests.
func GetTestDB(t *testing.T) *sql.DB {
	t.Helper()
	baseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if baseURL != "" {
		return openTestPostgres(t, baseURL)
	}
	return openTestSQLite(t)
}

func openTestSQLite(t *testing.T) *sql.DB {
	t.Helper()
	db.NoPlaceholders = true
	d, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'admin',
			created_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			name TEXT NOT NULL,
			key_hash TEXT NOT NULL,
			scope TEXT DEFAULT 'read',
			rate_limit INTEGER DEFAULT 100,
			created_at TEXT DEFAULT (datetime('now')),
			last_used_at TEXT DEFAULT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS bans (
			id TEXT PRIMARY KEY,
			ip TEXT NOT NULL,
			reason TEXT,
			hwid TEXT DEFAULT NULL,
			created_by TEXT DEFAULT NULL,
			banned_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE INDEX IF NOT EXISTS idx_bans_ip ON bans(ip)`,
	} {
		if _, err := d.Exec(stmt); err != nil {
			d.Close()
			t.Fatalf("create sqlite schema: %v", err)
		}
	}
	t.Cleanup(func() { d.Close() })
	return d
}
func openTestPostgres(t *testing.T, baseURL string) *sql.DB {
	t.Helper()
	admin, err := db.OpenPostgres(baseURL)
	if err != nil {
		t.Fatalf("open TEST_DATABASE_URL: %v", err)
	}
	schema := "test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(`CREATE SCHEMA "` + schema + `"`); err != nil {
		admin.Close()
		t.Fatalf("create test schema: %v", err)
	}
	admin.Close()

	targetURL, err := schemaURL(baseURL, schema)
	if err != nil {
		t.Fatalf("configure test schema: %v", err)
	}
	d, err := db.OpenPostgres(targetURL)
	if err != nil {
		t.Fatalf("open test schema: %v", err)
	}
	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		d.Close()
		t.Fatalf("run PostgreSQL migrations: %v", err)
	}
	t.Cleanup(func() {
		d.Close()
		cleanup, err := db.OpenPostgres(baseURL)
		if err != nil {
			t.Errorf("reopen test database for cleanup: %v", err)
			return
		}
		defer cleanup.Close()
		if _, err := cleanup.Exec(`DROP SCHEMA "` + schema + `" CASCADE`); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})
	return d
}

// OpenTestDB creates an isolated schema in TEST_DATABASE_URL and runs the
// canonical migrations. Tests fail hard when the PostgreSQL service is absent.
func OpenTestDB(t *testing.T) *sql.DB {
	t.Helper()
	baseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if baseURL == "" {
		t.Fatal("TEST_DATABASE_URL is required for PostgreSQL tests")
	}
	return openTestPostgres(t, baseURL)
}

func schemaURL(raw, schema string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("options", fmt.Sprintf("-csearch_path=%s,public", schema))
	u.RawQuery = q.Encode()
	return u.String(), nil
}

