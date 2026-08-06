package db

import "testing"

func TestNow(t *testing.T) {
	if got := Now(); got != "CURRENT_TIMESTAMP" {
		t.Errorf("Now() = %q, want CURRENT_TIMESTAMP", got)
	}
}

func TestUUID(t *testing.T) {
	if got := UUID(); got != "gen_random_uuid()::text" {
		t.Errorf("UUID() = %q", got)
	}
}

func TestPlaceholders(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"basic", "SELECT * FROM x WHERE a = ? AND b = ?", "SELECT * FROM x WHERE a = $1 AND b = $2"},
		{"single", "SELECT NOW()", "SELECT NOW()"},
		{"three", "INSERT INTO t VALUES (?, ?, ?)", "INSERT INTO t VALUES ($1, $2, $3)"},
		{"no question marks", "SELECT 1", "SELECT 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Placeholders(c.in); got != c.want {
				t.Errorf("Placeholders(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
