package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestAuthCleanupPaths(t *testing.T) {
	d := testutil.OpenTestDB(t)
	createTestUser(t, d, "cleanup-user", "secret123")

	handler := api.NewAuthHandler(d, "test-secret")
	r := chi.NewRouter()
	r.Post("/api/auth/login", handler.Login)
	r.Get("/api/auth/me", handler.Me)

	// Login with wrong password to trigger failedAttempts storage
	loginBody := `{"username":"cleanup-user","password":"wrongpass"}`
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(loginBody)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		_ = w.Code
	}
}

func TestAuthMe(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "me-user", "secret123")

	handler := api.NewAuthHandler(d, "test-secret")
	r := chi.NewRouter()
	r.Get("/api/auth/me", handler.Me)

	// Use claims context to bypass auth middleware
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("me: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	jsonDecode(t, w.Body.Bytes(), &resp)
	if resp["user_id"] != uid {
		t.Fatalf("me: bad body %s", w.Body.String())
	}
}
