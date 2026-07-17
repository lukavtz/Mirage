package db

import (
	"crypto/sha256"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"

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

	// ponytail: skip pg_* files (postgres, incompatible with sqlite)

	for _, name := range entries {
		if strings.HasPrefix(name, "pg_") {
			continue
		}
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

func RunMigrationsWithProvider(db *sql.DB, migrationsFS embed.FS, provider ProviderType) error {
	if provider == ProviderPostgres {
		return RunPGMigrations(db, migrationsFS)
	}
	return RunMigrations(db, MigrationsFS)
}

func RunPGMigrations(db *sql.DB, migrationsFS embed.FS) error {
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS _migrations (
			name        VARCHAR(255) PRIMARY KEY,
			hash        VARCHAR(64) NOT NULL,
			executed_at TIMESTAMP DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("create _migrations: %w", err)
	}

	entries, err := fs.Glob(migrationsFS, "migrations/pg_*.sql")
	if err != nil {
		entries = nil
	}

	entries2, err2 := fs.Glob(migrationsFS, "migrations/*.sql")
	if err2 != nil {
		return fmt.Errorf("list migrations: %w", err2)
	}

	seen := make(map[string]bool)
	for _, e := range entries {
		seen[e] = true
	}
	for _, e := range entries2 {
		if !seen[e] {
			entries = append(entries, e)
		}
		seen[e] = true
	}
	sort.Strings(entries)

	for _, name := range entries {
		content, err := fs.ReadFile(migrationsFS, name)
		if err != nil {
			content, err = fs.ReadFile(migrationsFS, "migrations/"+name)
			if err != nil {
				return fmt.Errorf("read %s: %w", name, err)
			}
		}

		sql := string(content)
		if !strings.HasPrefix(name, "pg_") {
			sql = translateSQLiteToPG(sql)
		}

		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(sql)))

		var existingHash string
		err = db.QueryRow("SELECT hash FROM _migrations WHERE name = $1", name).Scan(&existingHash)
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

		if _, err := tx.Exec(sql); err != nil {
			tx.Rollback()
			return fmt.Errorf("execute %s: %w", name, err)
		}

		if _, err := tx.Exec("INSERT INTO _migrations (name, hash) VALUES ($1, $2)", name, hash); err != nil {
			tx.Rollback()
			return fmt.Errorf("record %s: %w", name, err)
		}

		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit %s: %w", name, err)
		}
	}

	return nil
}

func translateSQLiteToPG(sql string) string {
	repl := map[string]string{
		" INTEGER PRIMARY KEY AUTOINCREMENT": " SERIAL PRIMARY KEY",
		" INTEGER PRIMARY KEY":               " SERIAL PRIMARY KEY",
		" BLOB":                              " BYTEA",
		" TEXT":                              " TEXT",
		"datetime('now')":                    "NOW()",
		"datetime('now',":                    "NOW() + INTERVAL '",
		" CURRENT_TIMESTAMP":                 " NOW()",
		"INSERT OR IGNORE":                   "INSERT",
	}

	result := sql
	for old, new := range repl {
		result = strings.ReplaceAll(result, old, new)
	}

	lines := strings.Split(result, "\n")
	var out []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(trimmed), "PRAGMA") {
			continue
		}
		out = append(out, line)
	}

	result = strings.Join(out, "\n")

	if !strings.Contains(strings.ToUpper(result), "ON CONFLICT") &&
		strings.HasPrefix(strings.ToUpper(strings.TrimSpace(result)), "INSERT") {
		upper := strings.ToUpper(result)
		tableEnd := strings.Index(upper, "(")
		if tableEnd != -1 {
			valuesIdx := strings.Index(upper[tableEnd:], "VALUES")
			// ponytail: skip INSERT...SELECT — ON CONFLICT requires a
			// conflict target on SELECT queries. Add explicit handling
			// when PostgreSQL INSERT...SELECT migrations are needed.
			if valuesIdx != -1 && !strings.Contains(upper, "SELECT") {
				result = result + " ON CONFLICT DO NOTHING"
			}
		}
	}

	return result
}
