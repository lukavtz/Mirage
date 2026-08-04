package db

import (
	"crypto/sha256"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
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

	// Build a set of pg_* overrides. A pg_NNN_x.sql file entirely replaces
	// the corresponding NNN_x.sql — the base file is skipped so PG-optimised
	// features (partial indexes, column types) take effect without duplicating
	// every CREATE TABLE in an override file.
	seen := make(map[string]bool)
	overrideOf := make(map[string]bool) // base name -> true
	for _, e := range entries {
		seen[e] = true
		// pg_027_sessions_owner.sql -> 027_sessions_owner.sql
		base := strings.TrimPrefix(e, "migrations/pg_")
		overrideOf[base] = true
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
		// If a pg_ override exists for this base file, skip the base file.
		if overrideOf[strings.TrimPrefix(name, "migrations/")] {
			continue
		}
		// pg_* files (paths like migrations/pg_000_init.sql) are already
		// PG-native — never run them through the SQLite translator, which
		// would trim newlines and corrupt their stored hash.
		if !strings.HasPrefix(name, "migrations/pg_") {
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
		"lower(hex(randomblob(16)))":        "gen_random_uuid()::text",
		" INTEGER PRIMARY KEY AUTOINCREMENT": " SERIAL PRIMARY KEY",
		" INTEGER PRIMARY KEY":               " SERIAL PRIMARY KEY",
		" BLOB":                              " BYTEA",
		" TEXT":                              " TEXT",
		" DATETIME":                          " TIMESTAMP",
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

	// Rewrite INSERT OR REPLACE INTO <t> (cols) VALUES (...) into
	// INSERT INTO <t> (cols) VALUES (...) ON CONFLICT (pk_cols) DO UPDATE SET ...
	// using the PK columns parsed from the preceding CREATE TABLE.
	result = rewriteInsertOrReplace(result)

	if !strings.Contains(strings.ToUpper(result), "ON CONFLICT") &&
		strings.HasPrefix(strings.ToUpper(strings.TrimSpace(result)), "INSERT") {
		upper := strings.ToUpper(result)
		tableEnd := strings.Index(upper, "(")
		if tableEnd != -1 {
			valuesIdx := strings.Index(upper[tableEnd:], "VALUES")
			if valuesIdx != -1 && !strings.Contains(upper, "SELECT") {
				result = strings.TrimRight(result, "; \t\r\n") + " ON CONFLICT DO NOTHING"
			}
		}
	}

	return result
}

// parseCreateTable extracts the column list and primary key columns from
// a CREATE TABLE statement. Returns nil if parsing fails.
//
// Handles the project's migration shape:
//
//	CREATE TABLE name (
//	    id   TEXT PRIMARY KEY,
//	    a    TEXT NOT NULL,
//	    b    INTEGER,
//	    PRIMARY KEY (id, a)
//	);
//
// and the inline PK variant: `name TEXT PRIMARY KEY`.
func parseCreateTable(stmt string) (table string, cols []string, pkCols []string) {
	upper := strings.ToUpper(stmt)
	if !strings.HasPrefix(upper, "CREATE TABLE") {
		return "", nil, nil
	}
	// Table name: between "CREATE TABLE" and the first "(".
	open := strings.Index(stmt, "(")
	if open < 0 {
		return "", nil, nil
	}
	head := strings.TrimSpace(stmt[len("CREATE TABLE"):open])
	// head may be "IF NOT EXISTS name" or just "name"; take the last word.
	parts := strings.Fields(head)
	if len(parts) == 0 {
		return "", nil, nil
	}
	table = parts[len(parts)-1]

	close := strings.LastIndex(stmt, ")")
	if close < 0 || close < open {
		return "", nil, nil
	}
	body := stmt[open+1 : close]

	// Split on top-level commas. The body's commas are not nested because
	// SQLite CREATE TABLE does not allow nested parens; the migration
	// format has no CHECK or DEFAULT that wraps a comma.
	for _, raw := range splitTopLevelCommas(body) {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		upperLine := strings.ToUpper(line)
		// Table-level PRIMARY KEY (a, b) clause.
		if strings.HasPrefix(upperLine, "PRIMARY KEY") {
			idx := strings.Index(line, "(")
			if idx < 0 {
				continue
			}
			end := strings.LastIndex(line, ")")
			if end < 0 {
				continue
			}
			for _, c := range strings.Split(line[idx+1:end], ",") {
				pkCols = append(pkCols, strings.TrimSpace(c))
			}
			continue
		}
		// Column definition: first whitespace-separated token is the name.
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}
		colName := strings.Trim(tokens[0], `"`)
		cols = append(cols, colName)
		// Inline PRIMARY KEY detection.
		if strings.Contains(upperLine, "PRIMARY KEY") {
			pkCols = append(pkCols, colName)
		}
	}
	return table, cols, pkCols
}

// splitTopLevelCommas splits on commas that are not inside parentheses.
// The project's migration CREATE TABLE bodies do not contain nested
// parens, so this naive split is safe.
func splitTopLevelCommas(s string) []string {
	var out []string
	depth := 0
	start := 0
	for i, r := range s {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// rewriteInsertOrReplace walks the SQL, tracking CREATE TABLE → INSERT OR
// REPLACE relationships. For each INSERT OR REPLACE, it builds the PG
// equivalent: INSERT INTO <t> (cols) VALUES (...) ON CONFLICT (pk_cols) DO
// UPDATE SET <non-pk col> = EXCLUDED.<col>. If the table was not seen
// (CREATE TABLE in a prior file) or has no detectable PK, it falls back
// to ON CONFLICT DO NOTHING.
func rewriteInsertOrReplace(sql string) string {
	type tableInfo struct{ cols, pkCols []string }
	tables := map[string]tableInfo{}

	// Collect CREATE TABLE definitions first.
	for _, stmt := range splitStatements(sql) {
		name, cols, pkCols := parseCreateTable(stmt)
		if name != "" {
			tables[name] = tableInfo{cols: cols, pkCols: pkCols}
		}
	}

	// Now rewrite INSERT OR REPLACE statements. We do not reorder; the
	// CREATE TABLE comes first in every migration file we ship.
	statements := splitStatements(sql)
	var out []string
	for _, stmt := range statements {
		trimmed := strings.TrimSpace(stmt)
		upper := strings.ToUpper(trimmed)
		if !strings.HasPrefix(upper, "INSERT OR REPLACE INTO ") {
			out = append(out, stmt)
			continue
		}
		// Parse "INSERT OR REPLACE INTO <t> (cols) VALUES (...)"
		after := strings.TrimSpace(trimmed[len("INSERT OR REPLACE INTO "):])
		open := strings.Index(after, "(")
		if open < 0 {
			out = append(out, stmt)
			continue
		}
		tableName := strings.TrimSpace(after[:open])
		// The column list runs to the matching ")".
		close := strings.Index(after[open:], ")")
		if close < 0 {
			out = append(out, stmt)
			continue
		}
		colList := strings.TrimSpace(after[open+1 : open+close])
		cols := splitCSV(colList)

		info, ok := tables[tableName]
		if !ok || len(info.pkCols) == 0 {
			// No CREATE TABLE seen or no PK; fall back to DO NOTHING and warn.
			slog.Warn("INSERT OR REPLACE without detected PK; falling back to ON CONFLICT DO NOTHING",
				"table", tableName, "statement", firstLine(trimmed))
			fallback := "INSERT INTO " + tableName + " (" + colList + ") " +
				after[open+close+1:] + " ON CONFLICT DO NOTHING"
			out = append(out, fallback)
			continue
		}
		// Build the ON CONFLICT (pk) DO UPDATE SET clause.
		setClauses := make([]string, 0, len(cols))
		for _, c := range cols {
			if contains(info.pkCols, c) {
				continue
			}
			setClauses = append(setClauses, c+" = EXCLUDED."+c)
		}
		if len(setClauses) == 0 {
			// Every column is a PK; nothing to update.
			fallback := "INSERT INTO " + tableName + " (" + colList + ") " +
				after[open+close+1:] + " ON CONFLICT DO NOTHING"
			out = append(out, fallback)
			continue
		}
		rewritten := "INSERT INTO " + tableName + " (" + colList + ") " +
			after[open+close+1:] +
			" ON CONFLICT (" + strings.Join(info.pkCols, ", ") + ") DO UPDATE SET " +
			strings.Join(setClauses, ", ")
		out = append(out, rewritten)
	}
	return strings.Join(out, "\n")
}

// splitStatements splits on top-level semicolons, ignoring empty parts.
// Each returned statement ends with a ";" so that drivers using the
// simple query protocol (e.g. pgx via database/sql) see a single
// terminator and the multi-statement input is preserved verbatim.
func splitStatements(sql string) []string {
	var out []string
	depth := 0
	start := 0
	for i, r := range sql {
		switch r {
		case '(':
			depth++
		case ')':
			depth--
		case ';':
			if depth == 0 {
				out = append(out, strings.TrimSpace(sql[start:i+1]))
				start = i + 1
			}
		}
	}
	if start < len(sql) {
		rest := strings.TrimSpace(sql[start:])
		if rest != "" {
			out = append(out, rest)
		}
	}
	return out
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		out = append(out, strings.TrimSpace(p))
	}
	return out
}

func contains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	if i := strings.Index(s, "\n"); i >= 0 {
		return s[:i]
	}
	return s
}

// migrationEntries returns the ordered migration file names for the given
// provider, in the same <name> form each runner writes into _migrations:
// plain *.sql without the "migrations/" prefix for SQLite (pg_* skipped),
// and pg_*.sql overrides + base files (minus overridden bases) with the
// "migrations/" prefix for PostgreSQL. Shared by RunMigrations,
// RunPGMigrations and VerifySchema.
func migrationEntries(migrationsFS embed.FS, provider ProviderType) ([]string, error) {
	all, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	if provider == ProviderSQLite {
		var out []string
		for _, e := range all {
			if strings.HasPrefix(e, "migrations/pg_") {
				continue
			}
			out = append(out, strings.TrimPrefix(e, "migrations/"))
		}
		sort.Strings(out)
		return out, nil
	}

	overrides, err := fs.Glob(migrationsFS, "migrations/pg_*.sql")
	if err != nil {
		overrides = nil
	}
	overrideOf := make(map[string]bool)
	for _, e := range overrides {
		overrideOf[strings.TrimPrefix(e, "migrations/pg_")] = true
	}
	var out []string
	out = append(out, overrides...)
	for _, e := range all {
		if overrideOf[strings.TrimPrefix(e, "migrations/")] {
			continue
		}
		out = append(out, e)
	}
	sort.Strings(out)
	return out, nil
}

// VerifySchema confirms every applied migration's hash matches the
// embedded content, for the given provider. Call it once at startup right
// after migrations run: a schema drifted from the code (hand-edited DB,
// deleted migration, hash mismatch) aborts startup instead of corrupting
// rows later.
func VerifySchema(db *sql.DB, migrationsFS embed.FS, provider ProviderType) error {
	entries, err := migrationEntries(migrationsFS, provider)
	if err != nil {
		return err
	}
	for _, name := range entries {
		path := name
		if provider == ProviderSQLite {
			path = "migrations/" + name
		}
		content, err := fs.ReadFile(migrationsFS, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		sql := string(content)
		if provider == ProviderPostgres && !strings.HasPrefix(name, "migrations/pg_") {
			sql = translateSQLiteToPG(sql)
		}
		want := fmt.Sprintf("%x", sha256.Sum256([]byte(sql)))
		ph := "?"
		if provider == ProviderPostgres {
			ph = "$1"
		}
		var got string
		if err := db.QueryRow("SELECT hash FROM _migrations WHERE name = "+ph, name).Scan(&got); err != nil {
			return fmt.Errorf("verify %s: not applied: %w", name, err)
		}
		if got != want {
			return fmt.Errorf("verify %s: hash mismatch (applied %s, want %s) — schema drifted from code", name, got, want)
		}
	}
	return nil
}
