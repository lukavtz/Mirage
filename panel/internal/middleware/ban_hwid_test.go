package middleware_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

func setupBanHWIDDB(t *testing.T) *sql.DB {
	t.Helper()
	f, err := os.CreateTemp("", "mirage-ban-hwid-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	d, err := db.OpenDB(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		d.Close()
		os.Remove(f.Name())
	})

	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec("INSERT INTO bans (id, ip, reason) VALUES ('b1', '192.168.1.100', 'test ban')")
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec("INSERT INTO bans (id, ip, hwid, reason) VALUES ('b2', '10.9.9.9', 'hwid-123', 'hwid ban')")
	if err != nil {
		t.Fatal(err)
	}

	return d
}

func TestBanCheck_BannedByHWID(t *testing.T) {
	d := setupBanHWIDDB(t)
	m := middleware.BanCheck(d)
	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for banned hwid")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.5:1234"
	req.Header.Set("X-HWID", "hwid-123")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for banned hwid, got %d", rec.Code)
	}
}

func TestBanCheck_HWIDNotBanned(t *testing.T) {
	d := setupBanHWIDDB(t)
	m := middleware.BanCheck(d)
	var called bool
	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.5:1234"
	req.Header.Set("X-HWID", "unknown-hwid")
	handler.ServeHTTP(rec, req)
	if !called {
		t.Error("next handler should be called for non-banned hwid")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}