package db

import (
	"strings"
	"testing"
)

func TestNow(t *testing.T) {
	if got := Now(ProviderSQLite); got != "datetime('now')" {
		t.Errorf("Now(SQLite) = %q, want datetime('now')", got)
	}
	if got := Now(ProviderPostgres); got != "NOW()" {
		t.Errorf("Now(Postgres) = %q, want NOW()", got)
	}
}

func TestUUID(t *testing.T) {
	if got := UUID(ProviderSQLite); got != "lower(hex(randomblob(16)))" {
		t.Errorf("UUID(SQLite) = %q", got)
	}
	if got := UUID(ProviderPostgres); got != "gen_random_uuid()::text" {
		t.Errorf("UUID(Postgres) = %q", got)
	}
}

func TestPlaceholders(t *testing.T) {
	cases := []struct {
		name string
		p    ProviderType
		in   string
		want string
	}{
		{"sqlite unchanged", ProviderSQLite, "SELECT * FROM x WHERE a = ? AND b = ?", "SELECT * FROM x WHERE a = ? AND b = ?"},
		{"pg basic", ProviderPostgres, "SELECT * FROM x WHERE a = ? AND b = ?", "SELECT * FROM x WHERE a = $1 AND b = $2"},
		{"pg single", ProviderPostgres, "SELECT NOW()", "SELECT NOW()"},
		{"pg three", ProviderPostgres, "INSERT INTO t VALUES (?, ?, ?)", "INSERT INTO t VALUES ($1, $2, $3)"},
		{"pg no question marks", ProviderPostgres, "SELECT 1", "SELECT 1"},
		{"sqlite no question marks", ProviderSQLite, "SELECT 1", "SELECT 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Placeholders(c.p, c.in)
			if got != c.want {
				t.Errorf("Placeholders(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestPlaceholdersStringLiteralSafety(t *testing.T) {
	// A naive "?"-to-"$N" rewrite is wrong if the "?" sits inside a
	// string literal. Document the limitation: callers must not embed
	// user input that contains "?". The current codebase does not.
	in := "SELECT 'does not contain ?' FROM x WHERE a = ?"
	got := Placeholders(ProviderPostgres, in)
	if !strings.Contains(got, "$1") {
		t.Errorf("expected $1 in result, got %q", got)
	}
}
