package db

import (
	"strings"
	"testing"
)

func TestTranslateSQLiteToPG_TypesAndDefaults(t *testing.T) {
	in := `CREATE TABLE t (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data BLOB,
    created DATETIME,
    updated TEXT DEFAULT (datetime('now', '+1 hour')),
    ts TEXT DEFAULT CURRENT_TIMESTAMP
);`
	got := translateSQLiteToPG(in)
	for _, want := range []string{
		"id SERIAL PRIMARY KEY",
		"data BYTEA",
		"created TIMESTAMP",
		"NOW() + INTERVAL '",
		"NOW()",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("expected %q in result, got:\n%s", want, got)
		}
	}
}

func TestTranslateSQLiteToPG_InsertOrIgnore(t *testing.T) {
	in := "INSERT OR IGNORE INTO settings (key, value) VALUES ('a', 'b');"
	got := translateSQLiteToPG(in)
	if strings.Contains(got, "OR IGNORE") {
		t.Errorf("INSERT OR IGNORE should become INSERT, got %q", got)
	}
	if !strings.Contains(got, "ON CONFLICT DO NOTHING") {
		t.Errorf("expected ON CONFLICT DO NOTHING fallback, got %q", got)
	}
}

func TestTranslateSQLiteToPG_InsertSelectNoConflict(t *testing.T) {
	in := "INSERT INTO t (a) SELECT b FROM src;"
	got := translateSQLiteToPG(in)
	if strings.Contains(got, "ON CONFLICT") {
		t.Errorf("SELECT-based INSERT should not get ON CONFLICT, got %q", got)
	}
}

func TestTranslateSQLiteToPG_MultiStatementWithComments(t *testing.T) {
	in := `-- init comment
CREATE TABLE a (id TEXT PRIMARY KEY);
-- second comment
PRAGMA foreign_keys = ON;
CREATE TABLE b (id TEXT PRIMARY KEY, ref TEXT);`
	got := translateSQLiteToPG(in)
	if strings.Contains(got, "PRAGMA") {
		t.Errorf("PRAGMA should be dropped, got %q", got)
	}
	if !strings.Contains(got, "-- init comment") {
		t.Errorf("comments should be preserved, got %q", got)
	}
	if !strings.Contains(got, "CREATE TABLE a") || !strings.Contains(got, "CREATE TABLE b") {
		t.Errorf("multi-statement translation lost statements, got %q", got)
	}
}

func TestTranslateSQLiteToPG_InsertOrReplaceWithPK(t *testing.T) {
	in := `CREATE TABLE t (id TEXT PRIMARY KEY, val TEXT);
INSERT OR REPLACE INTO t (id, val) VALUES ('x', 'y');`
	got := translateSQLiteToPG(in)
	if !strings.Contains(got, "ON CONFLICT (id) DO UPDATE SET val = EXCLUDED.val") {
		t.Errorf("expected ON CONFLICT with update, got:\n%s", got)
	}
}

func TestTranslateSQLiteToPG_InsertOrReplaceCompositePK(t *testing.T) {
	in := `CREATE TABLE t (a TEXT, b TEXT, c TEXT, PRIMARY KEY (a, b));
INSERT OR REPLACE INTO t (a, b, c) VALUES ('x', 'y', 'z');`
	got := translateSQLiteToPG(in)
	if !strings.Contains(got, "ON CONFLICT (a, b) DO UPDATE SET c = EXCLUDED.c") {
		t.Errorf("expected composite PK ON CONFLICT, got:\n%s", got)
	}
}

func TestTranslateSQLiteToPG_InsertOrReplaceAllPK(t *testing.T) {
	in := `CREATE TABLE single (id TEXT PRIMARY KEY);
INSERT OR REPLACE INTO single (id) VALUES ('x');`
	got := translateSQLiteToPG(in)
	if !strings.Contains(got, "ON CONFLICT DO NOTHING") {
		t.Errorf("all-PK INSERT OR REPLACE should become DO NOTHING, got:\n%s", got)
	}
}

func TestParseCreateTable_EdgeCases(t *testing.T) {
	cases := []struct {
		name    string
		stmt    string
		wantTbl string
		wantCol int
		wantPK  int
	}{
		{"not create table", "INSERT INTO x", "", -1, -1},
		{"no opening paren", "CREATE TABLE x", "", -1, -1},
		{"no closing paren", "CREATE TABLE x (a TEXT", "", -1, -1},
		{"no PK", "CREATE TABLE t (a TEXT, b INTEGER)", "t", 2, 0},
		{"empty body", "CREATE TABLE t ()", "t", 0, 0},
		{"stray trailing comma", "CREATE TABLE t (a TEXT,)", "t", 1, 0},
		{"quoted column name", "CREATE TABLE t (\"id\" TEXT PRIMARY KEY, \"name\" TEXT)", "t", 2, 1},
		{"table-level PK with inline PK", "CREATE TABLE t (a TEXT, b TEXT, PRIMARY KEY (a, b))", "t", 2, 2},
		{"empty table name", "CREATE TABLE (a TEXT)", "", -1, -1},
		{"PK clause without parens", "CREATE TABLE t (a TEXT, PRIMARY KEY)", "t", 1, 0},
		{"PK clause without close paren", "CREATE TABLE t (a TEXT, PRIMARY KEY (a)", "t", 1, 0},
		{"empty column entry", "CREATE TABLE t (, PRIMARY KEY (a))", "t", 0, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tbl, cols, pk := parseCreateTable(c.stmt)
			if tbl != c.wantTbl {
				t.Errorf("table = %q, want %q", tbl, c.wantTbl)
			}
			if c.wantCol < 0 {
				if cols != nil {
					t.Errorf("cols = %v, want nil", cols)
				}
			} else if len(cols) != c.wantCol {
				t.Errorf("len(cols) = %d, want %d; cols=%v", len(cols), c.wantCol, cols)
			}
			if c.wantPK < 0 {
				if pk != nil {
					t.Errorf("pk = %v, want nil", pk)
				}
			} else if len(pk) != c.wantPK {
				t.Errorf("len(pk) = %d, want %d; pk=%v", len(pk), c.wantPK, pk)
			}
		})
	}
}

func TestSplitStatements(t *testing.T) {
	cases := []struct {
		name string
		sql  string
		want int
	}{
		{"two statements", "SELECT 1; SELECT 2;", 2},
		{"single with parens", "CREATE TABLE t (a TEXT, b TEXT);", 1},
		{"semicolon inside parens", "INSERT INTO t (a) VALUES ((SELECT 1)); SELECT 2;", 2},
		{"trailing content", "SELECT 1", 1},
		{"empty", "", 0},
		{"whitespace only", "   ", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := splitStatements(c.sql)
			if len(got) != c.want {
				t.Errorf("len = %d, want %d; got=%v", len(got), c.want, got)
			}
		})
	}

	got := splitStatements("SELECT 1; SELECT 2")
	if len(got) != 2 {
		t.Fatalf("expected 2 parts, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[1], "SELECT 2") {
		t.Errorf("second part should contain SELECT 2, got %q", got[1])
	}
}

func TestSplitStatements_NestedParens(t *testing.T) {
	got := splitStatements("INSERT INTO t (a) VALUES (1); SELECT (2;3)")
	if len(got) != 2 {
		t.Fatalf("expected 2 statements, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[1], "SELECT (2;3)") {
		t.Errorf("second statement should preserve inner semicolon, got %q", got[1])
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("a\nb"); got != "a" {
		t.Errorf("firstLine with newline = %q, want %q", got, "a")
	}
	if got := firstLine("abc"); got != "abc" {
		t.Errorf("firstLine without newline = %q, want %q", got, "abc")
	}
}

func TestRewriteInsertOrReplace_MissingParens(t *testing.T) {
	in := "INSERT OR REPLACE INTO t;"
	got := rewriteInsertOrReplace(in)
	if !strings.Contains(got, "INSERT OR REPLACE") {
		t.Errorf("should preserve unparseable stmt, got %q", got)
	}

	in2 := "INSERT OR REPLACE INTO t (a"
	got2 := rewriteInsertOrReplace(in2)
	if !strings.Contains(got2, "INSERT OR REPLACE") {
		t.Errorf("should preserve unparseable stmt, got %q", got2)
	}
}

func TestRewriteInsertOrReplace_MultiLineFallback(t *testing.T) {
	in := "INSERT OR REPLACE INTO orphan (a, b)\nVALUES (1, 2);"
	got := rewriteInsertOrReplace(in)
	if !strings.Contains(got, "ON CONFLICT DO NOTHING") {
		t.Errorf("expected fallback DO NOTHING, got %q", got)
	}
}

func TestContains(t *testing.T) {
	if !contains([]string{"a", "b", "c"}, "b") {
		t.Error("contains should find 'b'")
	}
	if contains([]string{"a", "b", "c"}, "z") {
		t.Error("contains should not find 'z'")
	}
	if contains(nil, "x") {
		t.Error("contains nil should be false")
	}
}

func TestSplitTopLevelCommas_Nested(t *testing.T) {
	got := splitTopLevelCommas("a, (b, c), d")
	want := []string{"a", " (b, c)", " d"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("part %d = %q, want %q", i, got[i], want[i])
		}
	}
}
