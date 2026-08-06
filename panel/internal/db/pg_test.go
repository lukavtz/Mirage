package db_test

import (
	"testing"

	"zialfi-panel/internal/db"
	"zialfi-panel/internal/testutil"
)

// TestPGMigrations confirms the canonical migration chain creates tenant-owned
// columns in a real PostgreSQL schema.
func TestPGMigrations(t *testing.T) {
	d := testutil.OpenTestDB(t)
	if _, err := d.Query("SELECT owner_id FROM sessions LIMIT 0"); err != nil {
		t.Fatalf("sessions.owner_id not queryable: %v", err)
	}
	if _, err := d.Query("SELECT user_id FROM builds LIMIT 0"); err != nil {
		t.Fatalf("builds.user_id not queryable: %v", err)
	}
}
func TestPGSearchIndexes(t *testing.T) {
	d := testutil.OpenTestDB(t)

	var extensionExists bool
	if err := d.QueryRow("SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm')").Scan(&extensionExists); err != nil {
		t.Fatalf("check pg_trgm extension: %v", err)
	}
	if !extensionExists {
		t.Fatal("pg_trgm extension is not installed")
	}

	rows, err := d.Query(`SELECT indexname FROM pg_indexes
		WHERE schemaname = current_schema()
		AND indexname IN ('idx_passwords_search_trgm', 'idx_cookies_search_trgm', 'idx_cards_search_trgm', 'idx_wallets_search_trgm')`)
	if err != nil {
		t.Fatalf("query search indexes: %v", err)
	}
	defer rows.Close()
	found := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan search index: %v", err)
		}
		found[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate search indexes: %v", err)
	}
	for _, name := range []string{"idx_passwords_search_trgm", "idx_cookies_search_trgm", "idx_cards_search_trgm", "idx_wallets_search_trgm"} {
		if !found[name] {
			t.Errorf("search index %s is missing", name)
		}
	}
}

func TestRunMigrations_Idempotent(t *testing.T) {
	d := testutil.OpenTestDB(t)
	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatalf("second canonical migration run: %v", err)
	}
}
