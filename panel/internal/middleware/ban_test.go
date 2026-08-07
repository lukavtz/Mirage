package middleware_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func setupBanDB(t *testing.T) *sql.DB {
	t.Helper()
	d := testutil.GetTestDB(t)
	if _, err := d.Exec("INSERT INTO bans (id, ip, reason) VALUES ('b1', '192.168.1.100', 'test ban')"); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestBanCheck_NonBanned(t *testing.T) {
	d := setupBanDB(t)
	m := middleware.BanCheck(d)

	var called bool
	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler should be called for non-banned IP")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestBanCheck_BannedIP(t *testing.T) {
	d := setupBanDB(t)
	m := middleware.BanCheck(d)

	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for banned IP")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:54321"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestBanCheck_CacheReducesDBQueries(t *testing.T) {
	d := setupBanDB(t)

	queryCount := 0
	wd := &wrapDB{DB: d, counter: &queryCount}
	m := middleware.BanCheck(wd)

	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	if queryCount > 2 {
		t.Errorf("expected at most 2 DB queries (cache miss + maybe store), got %d", queryCount)
	}
}

func TestBanCheck_CacheBanned(t *testing.T) {
	d := setupBanDB(t)
	m := middleware.BanCheck(d)

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.100:12345"
		handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("next handler should not be called")
		}))
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("request %d: expected 403, got %d", i+1, rec.Code)
		}
	}
}

type wrapDB struct {
	*sql.DB
	counter *int
}

func (w *wrapDB) QueryRow(query string, args ...interface{}) *sql.Row {
	*w.counter++
	return w.DB.QueryRow(query, args...)
}
