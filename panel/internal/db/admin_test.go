package db_test

import (
	"testing"

	"zialfi-panel/internal/db"
)

func TestIsDefaultAdminPassword_Placeholder(t *testing.T) {
	d := openTestDB(t)
	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatal(err)
	}

	set, err := db.IsDefaultAdminPassword(d)
	if err != nil {
		t.Fatal(err)
	}
	if !set {
		t.Error("expected placeholder admin hash to be reported as default")
	}
}

func TestIsDefaultAdminPassword_Changed(t *testing.T) {
	d := openTestDB(t)
	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatal(err)
	}

	if _, err := d.Exec("UPDATE users SET password_hash = ? WHERE id = 'u_admin'", "$2a$12$fakehash"); err != nil {
		t.Fatal(err)
	}

	set, err := db.IsDefaultAdminPassword(d)
	if err != nil {
		t.Fatal(err)
	}
	if set {
		t.Error("expected changed hash not to be reported as default")
	}
}
