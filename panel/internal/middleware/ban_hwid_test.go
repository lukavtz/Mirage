package middleware_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func setupBanHWIDDB(t *testing.T) *sql.DB {
	t.Helper()
	d := testutil.GetTestDB(t)
	if _, err := d.Exec("INSERT INTO bans (id, ip, hwid, reason) VALUES ('b1', '192.168.1.100', 'hwid-123', 'test ban')"); err != nil {
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
