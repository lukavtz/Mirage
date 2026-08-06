package db

import (
	"database/sql"
	"fmt"
	"strings"
)

func Now() string { return "CURRENT_TIMESTAMP" }

func UUID() string { return "gen_random_uuid()::text" }

// Placeholders rewrites ? parameters to PostgreSQL positional parameters.
func Placeholders(query string) string {
	if !strings.Contains(query, "?") {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	for i, n := 0, 1; i < len(query); i++ {
		if query[i] == '?' {
			fmt.Fprintf(&b, "$%d", n)
			n++
		} else {
			b.WriteByte(query[i])
		}
	}
	return b.String()
}

func Exec(d *sql.DB, query string, args ...any) (sql.Result, error) {
	return d.Exec(Placeholders(query), args...)
}

func Query(d *sql.DB, query string, args ...any) (*sql.Rows, error) {
	return d.Query(Placeholders(query), args...)
}

func QueryRow(d *sql.DB, query string, args ...any) *sql.Row {
	return d.QueryRow(Placeholders(query), args...)
}
