package middleware_test

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

func setupAPIKeyDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "mirage-apikey-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	d, err := db.OpenDB(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatal(err)
	}

	userID := uuid.New().String()
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
		userID, "apikey-user", "x", "worker"); err != nil {
		t.Fatal(err)
	}

	raw := uuid.New().String() + uuid.New().String()
	hash := sha256.Sum256([]byte(raw))
	if _, err := d.Exec("INSERT INTO api_keys (id, user_id, name, key_hash) VALUES (?, ?, ?, ?)",
		uuid.New().String(), userID, "test-key", fmt.Sprintf("%x", hash)); err != nil {
		t.Fatal(err)
	}

	return d, raw
}

func newAPIKeyRouter(d *sql.DB) http.Handler {
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(d))
		r.Post("/api/log", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("ok"))
		})
	})
	return r
}

func TestAPIKeyAuth_MissingHeader_Rejected(t *testing.T) {
	d, _ := setupAPIKeyDB(t)
	r := newAPIKeyRouter(d)

	req := httptest.NewRequest(http.MethodPost, "/api/log", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without X-API-Key, got %d", w.Code)
	}
}

func TestAPIKeyAuth_ValidKey_Passes(t *testing.T) {
	d, raw := setupAPIKeyDB(t)
	r := newAPIKeyRouter(d)

	req := httptest.NewRequest(http.MethodPost, "/api/log", nil)
	req.Header.Set("X-API-Key", raw)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid key, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeyAuth_InvalidKey_Rejected(t *testing.T) {
	d, _ := setupAPIKeyDB(t)
	r := newAPIKeyRouter(d)

	req := httptest.NewRequest(http.MethodPost, "/api/log", nil)
	req.Header.Set("X-API-Key", "no-such-key")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with unknown key, got %d", w.Code)
	}
}
