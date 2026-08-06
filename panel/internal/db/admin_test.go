package db_test

import (
	"testing"

	"zialfi-panel/internal/db"
	"zialfi-panel/internal/testutil"
)

func TestIsDefaultAdminPassword_Placeholder(t *testing.T) {
	d := testutil.OpenTestDB(t)
	set, err := db.IsDefaultAdminPassword(d)
	if err != nil {
		t.Fatal(err)
	}
	if !set {
		t.Error("expected placeholder admin hash to be reported as default")
	}
}

func TestIsDefaultAdminPassword_Changed(t *testing.T) {
	d := testutil.OpenTestDB(t)
	if _, err := d.Exec("UPDATE users SET password_hash = $1 WHERE id = $2", "$2a$12$fakehash", "u_admin"); err != nil {
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
