package db_test

import (
	"database/sql"
	"embed"
	"os"
	"path/filepath"
	"testing"

	"zialfi-panel/internal/db"
)

//go:embed migrations/*.sql
var verifyFS embed.FS

// TestVerifySchema_SQLite runs migrations then confirms VerifySchema
// passes; a corrupted stored hash fails it.
func TestVerifySchema_SQLite(t *testing.T) {
	d := sqliteTestDB(t)

	if err := db.RunMigrationsWithProvider(d, verifyFS, db.ProviderSQLite); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.VerifySchema(d, verifyFS, db.ProviderSQLite); err != nil {
		t.Fatalf("VerifySchema after clean migrate: %v", err)
	}

	// Corrupt one stored hash → VerifySchema must fail.
	if _, err := d.Exec("UPDATE _migrations SET hash = 'deadbeef' WHERE name = '001_users.sql'"); err != nil {
		t.Fatal(err)
	}
	if err := db.VerifySchema(d, verifyFS, db.ProviderSQLite); err == nil {
		t.Fatal("VerifySchema succeeded despite corrupted migration hash")
	}
}

// TestVerifySchema_Postgres is the same on a live PG when DATABASE_URL
// is set; skipped otherwise.
func TestVerifySchema_Postgres(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping live PG verify test")
	}
	sqlDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := sqlDB.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	if err := db.RunPGMigrations(sqlDB, verifyFS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.VerifySchema(sqlDB, verifyFS, db.ProviderPostgres); err != nil {
		t.Fatalf("VerifySchema after clean PG migrate: %v", err)
	}

	if _, err := sqlDB.Exec("UPDATE _migrations SET hash='deadbeef' WHERE name='migrations/001_users.sql'"); err != nil {
		t.Fatal(err)
	}
	if err := db.VerifySchema(sqlDB, verifyFS, db.ProviderPostgres); err == nil {
		t.Fatal("VerifySchema succeeded despite corrupted PG migration hash")
	}
}

func sqliteTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	d, err := db.OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}
