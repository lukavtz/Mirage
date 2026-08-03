package db_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"zialfi-panel/internal/db"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	f, err := os.CreateTemp("", "mirage-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	d, err := db.OpenDB(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Close()
		os.Remove(f.Name())
	})
	return d
}

func TestOpenDB(t *testing.T) {
	d := openTestDB(t)
	if d == nil {
		t.Fatal("OpenDB returned nil")
	}
	if err := d.Ping(); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
}

func TestOpenDB_InvalidPath(t *testing.T) {
	_, err := db.OpenDB("/nonexistent/dir/test.db")
	if err == nil {
		t.Fatal("expected error for invalid path")
	}
}

func TestRunMigrations(t *testing.T) {
	d := openTestDB(t)

	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatalf("RunMigrations failed: %v", err)
	}

	tables := []string{
		"users", "sessions", "passwords", "cookies",
		"cards", "wallets", "stolen_files", "system_info",
		"settings", "bans", "_migrations",
		"invite_codes", "session_locks", "screenshots",
	}
	for _, table := range tables {
		var name string
		err := d.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found: %v", table, err)
		}
	}

	var adminCount int
	if err := d.QueryRow("SELECT COUNT(*) FROM users WHERE username='admin'").Scan(&adminCount); err != nil {
		t.Fatalf("query admin user: %v", err)
	}
	if adminCount != 1 {
		t.Errorf("expected 1 admin user, got %d", adminCount)
	}

	var rateLimit string
	if err := d.QueryRow("SELECT value FROM settings WHERE key='rate_limit'").Scan(&rateLimit); err != nil {
		t.Fatalf("query rate_limit setting: %v", err)
	}
	if rateLimit != "100" {
		t.Errorf("expected rate_limit=100, got %q", rateLimit)
	}
}

func TestRunMigrations_Idempotent(t *testing.T) {
	d := openTestDB(t)

	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatalf("first run failed: %v", err)
	}
	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatalf("second run failed: %v", err)
	}
}

func TestRunMigrations_RollbackOnError(t *testing.T) {
	d := openTestDB(t)

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "001_bad.sql"), []byte("CREATE TABLE corrupt_table;"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "002_good.sql"), []byte("CREATE TABLE should_not_exist (id TEXT PRIMARY KEY);"), 0644); err != nil {
		t.Fatal(err)
	}

	err := db.RunMigrations(d, os.DirFS(dir))
	if err == nil {
		t.Fatal("expected error for bad migration")
	}

	var name string
	err = d.QueryRow(
		"SELECT name FROM sqlite_master WHERE type='table' AND name='should_not_exist'",
	).Scan(&name)
	if err == nil {
		t.Error("table 'should_not_exist' was created despite migration failure")
	}
}
