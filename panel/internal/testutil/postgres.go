package testutil

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"zialfi-panel/internal/db"
)

// OpenTestDB creates an isolated schema in TEST_DATABASE_URL and runs the
// canonical migrations. Tests fail hard when the PostgreSQL service is absent.
func OpenTestDB(t *testing.T) *sql.DB {
	t.Helper()
	baseURL := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL"))
	if baseURL == "" {
		t.Fatal("TEST_DATABASE_URL is required for PostgreSQL tests")
	}

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
