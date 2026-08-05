package db_test

import (
	"path/filepath"
	"testing"

	"zialfi-panel/internal/db"
)

func TestExec(t *testing.T) {
	d := openTestDB(t)

	res, err := db.Exec(d, db.ProviderSQLite, "CREATE TABLE t (k TEXT PRIMARY KEY, v TEXT)")
	if err != nil {
		t.Fatal(err)
	}
	n, _ := res.RowsAffected()
	if n != 0 {
		t.Errorf("expected 0 rows affected, got %d", n)
	}

	res, err = db.Exec(d, db.ProviderPostgres, "INSERT INTO t (k, v) VALUES ($1, $2)", "k1", "v1")
	if err != nil {
		t.Fatal(err)
	}
	n, err = res.RowsAffected()
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 row affected, got %d", n)
	}
}

func TestQuery(t *testing.T) {
	d := openTestDB(t)
	if _, err := db.Exec(d, db.ProviderSQLite, "CREATE TABLE t (k TEXT PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(d, db.ProviderSQLite, "INSERT INTO t (k, v) VALUES ('a', 'b')"); err != nil {
		t.Fatal(err)
	}

	rows, err := db.Query(d, db.ProviderSQLite, "SELECT k, v FROM t ORDER BY k")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	if !rows.Next() {
		t.Fatal("expected at least one row")
	}
}

func TestQueryRow(t *testing.T) {
	d := openTestDB(t)
	if _, err := db.Exec(d, db.ProviderSQLite, "CREATE TABLE t (k TEXT PRIMARY KEY, v TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(d, db.ProviderSQLite, "INSERT INTO t (k, v) VALUES ('a', 'b')"); err != nil {
		t.Fatal(err)
	}

	var v string
	err := db.QueryRow(d, db.ProviderSQLite, "SELECT v FROM t WHERE k = ?", "a").Scan(&v)
	if err != nil {
		t.Fatal(err)
	}
	if v != "b" {
		t.Errorf("expected v=b, got %q", v)
	}
}

func TestNewProvider(t *testing.T) {
	p := db.NewProvider(db.ProviderSQLite, filepath.Join(t.TempDir(), "test.db"))
	if p.Type() != db.ProviderSQLite {
		t.Errorf("expected SQLite provider, got %v", p.Type())
	}
	d, err := p.Open()
	if err != nil {
		t.Fatal(err)
	}
	d.Close()

	d2 := openTestDB(t)
	if err := p.RunMigrations(d2, ""); err != nil {
		t.Fatalf("RunMigrations on SQLiteProvider: %v", err)
	}
}

func TestNewProvider_Postgres(t *testing.T) {
	p := db.NewProvider(db.ProviderPostgres, "postgres://invalid:5432/test?sslmode=disable")
	if p.Type() != db.ProviderPostgres {
		t.Errorf("expected Postgres provider, got %v", p.Type())
	}
	_, err := p.Open()
	if err == nil {
		t.Skip("Postgres is available; this test expects no live PG")
	}
}

func TestPostgresProvider_RunMigrationsOnSQLite(t *testing.T) {
	p := db.NewProvider(db.ProviderPostgres, "postgres://ignored:5432/test?sslmode=disable")
	d := openTestDB(t)
	if err := p.RunMigrations(d, ""); err != nil {
		t.Fatalf("PostgresProvider.RunMigrations on sqlite: %v", err)
	}
}

func TestIsDefaultAdminPassword_NoRows(t *testing.T) {
	d := openTestDB(t)
	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("DELETE FROM users WHERE id = 'u_admin'"); err != nil {
		t.Fatal(err)
	}
	set, err := db.IsDefaultAdminPassword(d)
	if err != nil {
		t.Fatal(err)
	}
	if set {
		t.Error("expected false when admin user is missing")
	}
}

func TestIsDefaultAdminPassword_QueryError(t *testing.T) {
	d := openTestDB(t)
	_, err := db.IsDefaultAdminPassword(d)
	if err == nil {
		t.Error("expected error when users table does not exist")
	}
}

func TestProviderSQLite_RunMigrations(t *testing.T) {
	p := db.NewProvider(db.ProviderSQLite, "")
	d := openTestDB(t)
	if err := p.RunMigrations(d, ""); err != nil {
		t.Fatalf("SQLiteProvider.RunMigrations: %v", err)
	}
	if err := p.RunMigrations(d, ""); err != nil {
		t.Fatalf("SQLiteProvider.RunMigrations second run: %v", err)
	}
}

func TestProviderSQLite_OpenError(t *testing.T) {
	_, err := db.NewProvider(db.ProviderSQLite, "/nonexistent/foo.db").Open()
	if err == nil {
		t.Error("expected error for invalid path")
	}
}

func TestPostgresProvider_OpenError(t *testing.T) {
	p := db.NewProvider(db.ProviderPostgres, "postgres://invalid:5432/bogus?sslmode=disable")
	_, err := p.Open()
	if err == nil {
		t.Skip("Postgres is available; this test expects no live PG")
	}
}

func TestPostgresProvider_Type(t *testing.T) {
	p := db.NewProvider(db.ProviderPostgres, "")
	if p.Type() != db.ProviderPostgres {
		t.Errorf("expected Postgres type, got %v", p.Type())
	}
}

func TestSQLiteProvider_Type(t *testing.T) {
	p := db.NewProvider(db.ProviderSQLite, "")
	if p.Type() != db.ProviderSQLite {
		t.Errorf("expected SQLite type, got %v", p.Type())
	}
}

func TestPlaceholdersPG(t *testing.T) {
	d := openTestDB(t)
	if _, err := db.Exec(d, db.ProviderPostgres, "CREATE TABLE t (k TEXT PRIMARY KEY, v TEXT, x TEXT)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(d, db.ProviderPostgres, "INSERT INTO t (k, v, x) VALUES ($1, $2, $3)", "a", "b", "c"); err != nil {
		t.Fatal(err)
	}
	var v, x string
	if err := db.QueryRow(d, db.ProviderPostgres, "SELECT v, x FROM t WHERE k = $1", "a").Scan(&v, &x); err != nil {
		t.Fatal(err)
	}
	if v != "b" || x != "c" {
		t.Errorf("expected v=b x=c, got v=%q x=%q", v, x)
	}
}

func TestRunMigrationsWithProvider_Direct(t *testing.T) {
	d := openTestDB(t)
	if err := db.RunMigrationsWithProvider(d, db.MigrationsFS, db.ProviderSQLite); err != nil {
		t.Fatalf("RunMigrationsWithProvider(SQLite): %v", err)
	}
	var count int
	if err := d.QueryRow("SELECT COUNT(*) FROM _migrations").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Error("expected migrations to be recorded")
	}
}
