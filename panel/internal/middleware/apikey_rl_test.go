package middleware_test

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func setupAPIKeyWithRateLimit(t *testing.T, rateLimit int) (*sql.DB, string) {
	t.Helper()
	d := testutil.OpenTestDB(t)
	userID := uuid.New().String()
	if _, err := d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES ($1, $2, $3, $4)", userID, "apikey-rl-user", "x", "worker"); err != nil {
		t.Fatal(err)
	}
	raw := uuid.New().String() + uuid.New().String()
	hash := sha256.Sum256([]byte(raw))
	if _, err := d.Exec("INSERT INTO api_keys (id, user_id, name, key_hash, rate_limit) VALUES ($1, $2, $3, $4, $5)", uuid.New().String(), userID, "rl-key", fmt.Sprintf("%x", hash), rateLimit); err != nil {
		t.Fatal(err)
	}
	return d, raw
}

func TestAPIKeyAuth_RateLimitExceeded(t *testing.T) {
	d, raw := setupAPIKeyWithRateLimit(t, 1)
	r := chi.NewRouter()
	r.Group(func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(d))
		r.Post("/api/log", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/log", nil)
		req.Header.Set("X-API-Key", raw)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if i == 0 && w.Code != http.StatusOK {
			t.Fatalf("first request: expected 200, got %d: %s", w.Code, w.Body.String())
		}
		if i == 1 && w.Code != http.StatusTooManyRequests {
			t.Fatalf("second request: expected 429, got %d: %s", w.Code, w.Body.String())
		}
	}
}
