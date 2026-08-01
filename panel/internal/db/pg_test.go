package db_test

import (
	"os"
	"testing"

	"zialfi-panel/internal/db"
)

// TestPGMigrations applies all migrations against a live PostgreSQL instance.
// Skipped unless DATABASE_URL is set, e.g.:
//
//	docker run -d --name mirage-pg-test -e POSTGRES_PASSWORD=test -p 5432:5432 postgres:16
//	DATABASE_URL='postgres://postgres:test@localhost:5432/postgres?sslmode=disable' \
//	  go test ./internal/db/ -run TestPGMigrations -count=1 -v
func TestPGMigrations(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping PostgreSQL migration smoke test")
	}

	p := db.NewProvider(db.ProviderPostgres, dsn)
	sqlDB, err := p.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()

	if err := db.RunPGMigrations(sqlDB, db.MigrationsFS); err != nil {
		t.Fatalf("RunPGMigrations: %v", err)
	}

	// tenant columns from 027/028 must exist and be queryable
	if _, err := sqlDB.Query("SELECT owner_id FROM sessions LIMIT 0"); err != nil {
		t.Fatalf("sessions.owner_id not queryable: %v", err)
	}
	if _, err := sqlDB.Query("SELECT user_id FROM builds LIMIT 0"); err != nil {
		t.Fatalf("builds.user_id not queryable: %v", err)
	}
}
