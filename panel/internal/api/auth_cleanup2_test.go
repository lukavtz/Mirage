package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/db"
)

func TestAuthCleanupFailedAttempts(t *testing.T) {
	d := openTestDB(t)
	createTestUser(t, d, "cleanup2", "secret123")

	handler := api.NewAuthHandler(d, "test-secret", db.ProviderSQLite)
	// Login with wrong password enough times to trigger failed_attempts
	// and allow cleanupFailedAttempts to run
	body := `{"username":"cleanup2","password":"wrongpass","ip":"10.0.0.1"}`
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Login(w, req)
		if w.Code == http.StatusOK {
			t.Fatal("login with wrong password should not succeed")
		}
	}
}

func TestAuthForgotPassword(t *testing.T) {
	d := openTestDB(t)
	createTestUser(t, d, "forgot-user", "secret123")

	handler := api.NewAuthHandler(d, "test-secret", db.ProviderSQLite)
	r := chi.NewRouter()
	r.Post("/api/auth/forgot-password", handler.ForgotPassword)
	r.Post("/api/auth/reset-password", handler.ResetPassword)

	// forgot password for nonexistent user → 200 (generic message)
	req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader([]byte(`{"username":"nonexistent"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("forgot nonexistent: expected 200, got %d", w.Code)
	}

	// forgot password with empty body → 400
	req = httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("forgot empty: expected 400, got %d", w.Code)
	}
}

func TestAuthResetPasswordEdgeCases(t *testing.T) {
	d := openTestDB(t)
	createTestUser(t, d, "reset-user", "secret123")

	handler := api.NewAuthHandler(d, "test-secret", db.ProviderSQLite)
	r := chi.NewRouter()
	r.Post("/api/auth/reset-password", handler.ResetPassword)

	// reset with empty body → 400
	req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("reset empty: expected 400, got %d", w.Code)
	}

	// reset with invalid token → 400
	req = httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader([]byte(`{"token":"invalid","new_password":"newpass12345"}`)))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("reset invalid token: expected 400, got %d", w.Code)
	}
}

func TestAuthRecordFailedAttempt(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewAuthHandler(d, "test-secret", db.ProviderSQLite)
	// recordFailedAttempt is called from Login with wrong password
	// it's an internal method, but we can trigger it through repeated login
	body := `{"username":"nonexistent","password":"x"}`
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Login(w, req)
		_ = w.Code
	}
}
