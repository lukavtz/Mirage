package db_test

import (
	"testing"

	"zialfi-panel/internal/db"
	"zialfi-panel/internal/testutil"
)

func TestVerifySchema(t *testing.T) {
	d := testutil.OpenTestDB(t)
	if err := db.VerifySchema(d, db.MigrationsFS); err != nil {
		t.Fatalf("VerifySchema after clean migrate: %v", err)
	}

	var origHash string
	if err := d.QueryRow("SELECT hash FROM _migrations WHERE name = $1", "migrations/001_users.sql").Scan(&origHash); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("UPDATE _migrations SET hash = $1 WHERE name = $2", "deadbeef", "migrations/001_users.sql"); err != nil {
		t.Fatal(err)
	}
	if err := db.VerifySchema(d, db.MigrationsFS); err == nil {
		t.Fatal("VerifySchema succeeded despite corrupted migration hash")
	}
	if _, err := d.Exec("UPDATE _migrations SET hash = $1 WHERE name = $2", origHash, "migrations/001_users.sql"); err != nil {
		t.Fatal(err)
	}
}
