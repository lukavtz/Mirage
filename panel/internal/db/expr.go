package db

import (
	"fmt"
	"strings"
)

// Now returns the dialect-correct SQL expression for "current timestamp at
// insert time". SQLite uses datetime('now'); PostgreSQL has NOW(). The
// returned string is meant to be embedded in a SQL string at parse time on
// the server's startup, never on a per-request user-supplied path.
func Now(p ProviderType) string {
	if p == ProviderPostgres {
		return "NOW()"
	}
	return "datetime('now')"
}

// UUID returns the dialect-correct SQL expression for a fresh UUID rendered
// as a lowercase hex / dashed text. Caller concatenates into a DEFAULT
// clause at parse time (e.g. when generating CREATE TABLE statements at
// server start), never on a per-request user-supplied path.
func UUID(p ProviderType) string {
	if p == ProviderPostgres {
		return "gen_random_uuid()::text"
	}
	return "lower(hex(randomblob(16)))"
}

// Placeholders rewrites every "?" in sql to "$1, $2, …, $N" when the
// provider is PostgreSQL; returns sql unchanged for SQLite. The driver
// pgx (via database/sql) requires $N placeholders; the sqlite driver
// (modernc.org/sqlite) accepts both. Use at the moment a query string is
// built; result is meant to be passed to db.Exec / db.Query / db.QueryRow
// once, not interpolated with user input.
func Placeholders(p ProviderType, sql string) string {
	if p != ProviderPostgres {
		return sql
	}
	if !strings.Contains(sql, "?") {
		return sql
	}
	var b strings.Builder
	b.Grow(len(sql) + 8)
	n := 1
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if c == '?' {
			fmt.Fprintf(&b, "$%d", n)
			n++
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}
