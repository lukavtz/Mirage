package db

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dbTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	d, err := OpenDB(path)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func writeMigDir(t *testing.T, files map[string]string) fs.FS {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return os.DirFS(dir)
}

func TestRunMigrations_HashMismatch(t *testing.T) {
	d := dbTestDB(t)
	fsys := writeMigDir(t, map[string]string{
		"001_x.sql": "CREATE TABLE x (id TEXT PRIMARY KEY);",
	})
	if err := RunMigrations(d, fsys); err != nil {
		t.Fatalf("first run: %v", err)
	}
	// Modify the file content; the stored hash no longer matches.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "001_x.sql"),
		[]byte("CREATE TABLE x (id TEXT PRIMARY KEY, extra TEXT);"), 0644); err != nil {
		t.Fatal(err)
	}
	err := RunMigrations(d, os.DirFS(dir))
	if err == nil {
		t.Fatal("expected hash mismatch error on second run")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("expected hash mismatch error, got %v", err)
	}
}

func TestRunPGMigrationsOnSQLite(t *testing.T) {
	d := dbTestDB(t)
	fsys := writeMigDir(t, map[string]string{
		"migrations/000_kv.sql":         "CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);",
		"migrations/001_base.sql":       "CREATE TABLE t_base (id TEXT PRIMARY KEY, name TEXT NOT NULL);",
		"migrations/pg_001_base.sql":    "CREATE TABLE t_base (id TEXT PRIMARY KEY, name TEXT NOT NULL, pg_only TEXT);",
		"migrations/002_pg_only.sql":    "CREATE TABLE pg_only_tbl (id TEXT PRIMARY KEY);",
		"migrations/pg_002_pg_only.sql": "CREATE TABLE pg_only_tbl (id TEXT PRIMARY KEY, pg_flag INTEGER);",
	})

	// Pre-create _migrations with a SQLite-compatible schema so the
	// runner's CREATE TABLE IF NOT EXISTS is a no-op (its PG-flavoured
	// DEFAULT NOW() would not run on SQLite).
	if _, err := d.Exec("CREATE TABLE _migrations (name TEXT PRIMARY KEY, hash TEXT NOT NULL, executed_at TEXT DEFAULT (datetime('now')))"); err != nil {
		t.Fatal(err)
	}

	if err := RunPGMigrations(d, fsys); err != nil {
		t.Fatalf("RunPGMigrations on sqlite: %v", err)
	}

	// The pg_ override replaces the base: only the override is recorded.
	var name string
	if err := d.QueryRow("SELECT name FROM _migrations WHERE name = 'migrations/pg_001_base.sql'").Scan(&name); err != nil {
		t.Errorf("pg_ override should be recorded: %v", err)
	}
	if err := d.QueryRow("SELECT name FROM _migrations WHERE name = 'migrations/001_base.sql'").Scan(&name); err == nil {
		t.Error("overridden base migration should NOT be recorded")
	}
	// The pg_only column proves the override (not the base) ran.
	var sqlText string
	if err := d.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='t_base'").Scan(&sqlText); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sqlText, "pg_only") {
		t.Errorf("t_base should be created from the pg_ override, got: %s", sqlText)
	}
	if err := d.QueryRow("SELECT name FROM _migrations WHERE name = 'migrations/002_pg_only.sql'").Scan(&name); err == nil {
		t.Error("overridden base 002_pg_only.sql should NOT be recorded")
	}
	if err := d.QueryRow("SELECT name FROM _migrations WHERE name = 'migrations/pg_002_pg_only.sql'").Scan(&name); err != nil {
		t.Errorf("pg_002_pg_only override should be recorded: %v", err)
	}

	// Idempotent re-run skips applied migrations.
	if err := RunPGMigrations(d, fsys); err != nil {
		t.Fatalf("second run should be a no-op, got: %v", err)
	}
}

func TestRunMigrationsWithProvider_Postgres(t *testing.T) {
	d := dbTestDB(t)
	fsys := writeMigDir(t, map[string]string{
		"migrations/000_kv.sql": "CREATE TABLE kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);",
	})
	if _, err := d.Exec("CREATE TABLE _migrations (name TEXT PRIMARY KEY, hash TEXT NOT NULL, executed_at TEXT DEFAULT (datetime('now')))"); err != nil {
		t.Fatal(err)
	}
	if err := RunMigrationsWithProvider(d, fsys, ProviderPostgres); err != nil {
		t.Fatalf("RunMigrationsWithProvider(PG): %v", err)
	}
	var name string
	if err := d.QueryRow("SELECT name FROM _migrations WHERE name = 'migrations/000_kv.sql'").Scan(&name); err != nil {
		t.Errorf("migration should be recorded: %v", err)
	}
}

func TestMigrationEntries(t *testing.T) {
	sqliteEntries, err := migrationEntries(MigrationsFS, ProviderSQLite)
	if err != nil {
		t.Fatal(err)
	}
	if len(sqliteEntries) == 0 {
		t.Fatal("expected SQLite migration entries")
	}
	for _, e := range sqliteEntries {
		if strings.HasPrefix(e, "pg_") {
			t.Errorf("SQLite entries must not contain pg_* files: %q", e)
		}
		if strings.HasPrefix(e, "migrations/") {
			t.Errorf("SQLite entries must not carry the migrations/ prefix: %q", e)
		}
	}

	pgEntries, err := migrationEntries(MigrationsFS, ProviderPostgres)
	if err != nil {
		t.Fatal(err)
	}
	foundOverride := false
	for _, e := range pgEntries {
		if !strings.HasPrefix(e, "migrations/") {
			t.Errorf("PG entries must carry the migrations/ prefix: %q", e)
		}
		if e == "migrations/pg_000_init.sql" {
			foundOverride = true
		}
		if e == "migrations/000_init.sql" {
			t.Errorf("base 000_init.sql should be replaced by its pg_ override")
		}
	}
	if !foundOverride {
		t.Error("expected migrations/pg_000_init.sql among PG entries")
	}
}

func TestRunMigrations_ReadError(t *testing.T) {
	d := dbTestDB(t)
	fsys := writeMigDir(t, map[string]string{
		"001_dir.sql/placeholder.txt": "x",
	})
	err := RunMigrations(d, fsys)
	if err == nil || !strings.Contains(err.Error(), "read 001_dir.sql") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestRunMigrations_RecordError(t *testing.T) {
	d := dbTestDB(t)
	if _, err := d.Exec("CREATE TABLE _migrations (name TEXT PRIMARY KEY, hash TEXT NOT NULL CHECK (length(hash) < 10), executed_at TEXT DEFAULT (datetime('now')))"); err != nil {
		t.Fatal(err)
	}
	fsys := writeMigDir(t, map[string]string{
		"001_x.sql": "CREATE TABLE x (id TEXT PRIMARY KEY);",
	})
	err := RunMigrations(d, fsys)
	if err == nil || !strings.Contains(err.Error(), "record 001_x.sql") {
		t.Fatalf("expected record error, got %v", err)
	}
	var name string
	err = d.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='x'").Scan(&name)
	if err == nil {
		t.Error("migration should have been rolled back after record failure")
	}
}

func TestRunPGMigrations_ReadError(t *testing.T) {
	d := dbTestDB(t)
	if _, err := d.Exec("CREATE TABLE _migrations (name TEXT PRIMARY KEY, hash TEXT NOT NULL, executed_at TEXT DEFAULT (datetime('now')))"); err != nil {
		t.Fatal(err)
	}
	fsys := writeMigDir(t, map[string]string{
		"migrations/001_dir.sql/placeholder.txt": "x",
	})
	err := RunPGMigrations(d, fsys)
	if err == nil || !strings.Contains(err.Error(), "read migrations/001_dir.sql") {
		t.Fatalf("expected read error, got %v", err)
	}
}

func TestVerifySchema_NotApplied(t *testing.T) {
	d := dbTestDB(t) // no migrations run; _migrations does not exist
	err := VerifySchema(d, MigrationsFS, ProviderSQLite)
	if err == nil {
		t.Fatal("expected error when no migrations are applied")
	}
	if !strings.Contains(err.Error(), "not applied") {
		t.Errorf("expected 'not applied' error, got %v", err)
	}
}

func TestVerifySchema_PostgresBranchOnSQLite(t *testing.T) {
	d := dbTestDB(t)
	if _, err := d.Exec("CREATE TABLE _migrations (name TEXT PRIMARY KEY, hash TEXT NOT NULL, executed_at TEXT DEFAULT (datetime('now')))"); err != nil {
		t.Fatal(err)
	}
	entries, err := migrationEntries(MigrationsFS, ProviderPostgres)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, name := range entries {
		if seen[name] {
			continue
		}
		seen[name] = true
		content, err := fs.ReadFile(MigrationsFS, name)
		if err != nil {
			t.Fatal(err)
		}
		sqlText := string(content)
		if !strings.HasPrefix(name, "migrations/pg_") {
			sqlText = translateSQLiteToPG(sqlText)
		}
		want := fmt.Sprintf("%x", sha256.Sum256([]byte(sqlText)))
		if _, err := d.Exec("INSERT INTO _migrations (name, hash) VALUES (?, ?)", name, want); err != nil {
			t.Fatal(err)
		}
	}

	if err := VerifySchema(d, MigrationsFS, ProviderPostgres); err != nil {
		t.Fatalf("VerifySchema(PG) against matching hashes: %v", err)
	}

	// Corrupt one stored hash → mismatch.
	if _, err := d.Exec("UPDATE _migrations SET hash = 'deadbeef' WHERE name = 'migrations/001_users.sql'"); err != nil {
		t.Fatal(err)
	}
	err = VerifySchema(d, MigrationsFS, ProviderPostgres)
	if err == nil {
		t.Fatal("expected hash mismatch error")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Errorf("expected hash mismatch error, got %v", err)
	}
}
