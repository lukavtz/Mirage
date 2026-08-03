package db

import (
	"strings"
	"testing"
)

func TestTranslateSQLiteToPG_DatetimeAndRandomblob(t *testing.T) {
	in := `CREATE TABLE x (id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))), created_at TEXT NOT NULL DEFAULT (datetime('now')));`
	got := translateSQLiteToPG(in)
	if !strings.Contains(got, "gen_random_uuid()::text") {
		t.Errorf("expected uuid rewrite, got %q", got)
	}
	if !strings.Contains(got, "NOW()") {
		t.Errorf("expected NOW() rewrite, got %q", got)
	}
}

func TestTranslateSQLiteToPG_InsertOrReplace(t *testing.T) {
	in := `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT DEFAULT (datetime('now')));
INSERT OR REPLACE INTO settings (key, value) VALUES ('rate_limit', '100');
`
	got := translateSQLiteToPG(in)
	if !strings.Contains(got, "INSERT INTO settings (key, value)") {
		t.Errorf("expected INSERT (no OR REPLACE) into settings, got %q", got)
	}
	if !strings.Contains(got, "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value") {
		t.Errorf("expected ON CONFLICT DO UPDATE SET for value, got %q", got)
	}
	if strings.Contains(got, "INSERT OR REPLACE") {
		t.Errorf("INSERT OR REPLACE should be stripped, got %q", got)
	}
}

func TestTranslateSQLiteToPG_InsertOrReplaceNoPK(t *testing.T) {
	// No preceding CREATE TABLE → fallback to DO NOTHING.
	in := "INSERT OR REPLACE INTO orphan (a, b) VALUES (1, 2);\n"
	got := translateSQLiteToPG(in)
	if !strings.Contains(got, "ON CONFLICT DO NOTHING") {
		t.Errorf("expected fallback ON CONFLICT DO NOTHING, got %q", got)
	}
}

func TestTranslateSQLiteToPG_InsertOrReplace_CompositePK(t *testing.T) {
	in := `CREATE TABLE session_tags (id TEXT PRIMARY KEY, session_id TEXT NOT NULL, tag TEXT NOT NULL, color TEXT NOT NULL, UNIQUE (session_id, tag));
INSERT OR REPLACE INTO session_tags (id, session_id, tag, color) VALUES ('x', 's', 'steam', 'red');
`
	got := translateSQLiteToPG(in)
	// session_tags has no PRIMARY KEY clause other than id; the inline
	// "id TEXT PRIMARY KEY" should be detected as the PK.
	if !strings.Contains(got, "ON CONFLICT (id) DO UPDATE SET") {
		t.Errorf("expected ON CONFLICT (id) for inline PK, got %q", got)
	}
}

func TestTranslateSQLiteToPG_PragmaDrop(t *testing.T) {
	in := "PRAGMA foreign_keys = ON;\nCREATE TABLE x (id TEXT PRIMARY KEY);"
	got := translateSQLiteToPG(in)
	if strings.Contains(got, "PRAGMA") {
		t.Errorf("PRAGMA should be stripped, got %q", got)
	}
}

func TestSplitCSV(t *testing.T) {
	got := splitCSV("a, b ,c")
	want := []string{"a", "b", "c"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("splitCSV = %v, want %v", got, want)
	}
}

func TestParseCreateTable(t *testing.T) {
	cases := []struct {
		name     string
		stmt     string
		wantTbl  string
		wantCols []string
		wantPK   []string
	}{
		{
			name:     "simple inline PK",
			stmt:     "CREATE TABLE users (id TEXT PRIMARY KEY, name TEXT NOT NULL)",
			wantTbl:  "users",
			wantCols: []string{"id", "name"},
			wantPK:   []string{"id"},
		},
		{
			name:     "IF NOT EXISTS",
			stmt:     "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)",
			wantTbl:  "settings",
			wantCols: []string{"key", "value"},
			wantPK:   []string{"key"},
		},
		{
			name:     "table-level PK",
			stmt:     "CREATE TABLE t (a TEXT, b TEXT, PRIMARY KEY (a, b))",
			wantTbl:  "t",
			wantCols: []string{"a", "b"},
			wantPK:   []string{"a", "b"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tbl, cols, pk := parseCreateTable(c.stmt)
			if tbl != c.wantTbl {
				t.Errorf("table = %q, want %q", tbl, c.wantTbl)
			}
			if !equalStringSlices(cols, c.wantCols) {
				t.Errorf("cols = %v, want %v", cols, c.wantCols)
			}
			if !equalStringSlices(pk, c.wantPK) {
				t.Errorf("pk = %v, want %v", pk, c.wantPK)
			}
		})
	}
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
