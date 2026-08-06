package db

import (
	"crypto/sha256"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
)

//go:embed migrations/*.sql
var MigrationsFS embed.FS

// RunMigrations applies the canonical PostgreSQL migration chain idempotently.
func RunMigrations(db *sql.DB, migrations fs.FS) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS _migrations (
		name TEXT PRIMARY KEY,
		hash TEXT NOT NULL,
		executed_at TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create _migrations: %w", err)
	}
	entries, err := fs.Glob(migrations, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(entries)
	for _, name := range entries {
		content, err := fs.ReadFile(migrations, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		hash := fmt.Sprintf("%x", sha256.Sum256(content))
		var existing string
		err = db.QueryRow("SELECT hash FROM _migrations WHERE name = $1", name).Scan(&existing)
		if err == nil {
			if existing == hash {
				continue
			}
			return fmt.Errorf("migration %s hash mismatch (was %s, now %s)", name, existing, hash)
		}
		if err != sql.ErrNoRows {
			return fmt.Errorf("check migration %s: %w", name, err)
		}
		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin %s: %w", name, err)
		}
		if _, err = tx.Exec(string(content)); err != nil {
			tx.Rollback()
			return fmt.Errorf("execute %s: %w", name, err)
		}
		if _, err = tx.Exec("INSERT INTO _migrations (name, hash) VALUES ($1, $2)", name, hash); err != nil {
			tx.Rollback()
			return fmt.Errorf("record %s: %w", name, err)
		}
		if err = tx.Commit(); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}
	return nil
}

// VerifySchema confirms every embedded migration was applied without drift.
func VerifySchema(db *sql.DB, migrationsFS embed.FS) error {
	entries, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(entries)
	for _, name := range entries {
		content, err := fs.ReadFile(migrationsFS, name)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		want := fmt.Sprintf("%x", sha256.Sum256(content))
		var got string
		if err := db.QueryRow("SELECT hash FROM _migrations WHERE name = $1", name).Scan(&got); err != nil {
			return fmt.Errorf("verify %s: not applied: %w", name, err)
		}
		if got != want {
			return fmt.Errorf("verify %s: hash mismatch (applied %s, want %s)", name, got, want)
		}
	}
	return nil
}
