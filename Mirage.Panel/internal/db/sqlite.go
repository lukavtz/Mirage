package db

import (
	"crypto/sha256"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var MigrationsFS embed.FS

func OpenDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}

	return db, nil
}

func RunMigrations(db *sql.DB, migrations fs.FS) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS _migrations (
			name        TEXT PRIMARY KEY,
			hash        TEXT NOT NULL,
			executed_at TEXT NOT NULL DEFAULT (datetime('now'))
		)
	`); err != nil {
		return fmt.Errorf("create _migrations: %w", err)
	}

	if _, err := fs.Stat(migrations, "migrations"); err == nil {
		sub, err := fs.Sub(migrations, "migrations")
		if err == nil {
			migrations = sub
		}
	}

	entries, err := fs.Glob(migrations, "*.sql")
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

		var existingHash string
		err = db.QueryRow("SELECT hash FROM _migrations WHERE name = ?", name).Scan(&existingHash)
		if err == nil {
			if existingHash == hash {
				continue
			}
			return fmt.Errorf("migration %s hash mismatch (was %s, now %s)", name, existingHash, hash)
		}

		tx, err := db.Begin()
		if err != nil {
			return fmt.Errorf("begin tx %s: %w", name, err)
		}

		if _, err := tx.Exec(string(content)); err != nil {
			tx.Rollback()
			return fmt.Errorf("execute %s: %w", name, err)
		}

		if _, err := tx.Exec("INSERT INTO _migrations (name, hash) VALUES (?, ?)", name, hash); err != nil {
			tx.Rollback()
			return fmt.Errorf("record %s: %w", name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}

	return nil
}
