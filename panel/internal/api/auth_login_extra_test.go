package api_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"zialfi-panel/internal/api"
	"zialfi-panel/internal/testutil"
)

func TestLogin_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewAuthHandler(d, "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(`bad`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Login(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_MissingFields_Extra(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewAuthHandler(d, "test-secret")

	cases := []string{`{}`, `{"username":"u"}`, `{"password":"p"}`}
	for _, body := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Login(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %s: expected 400, got %d: %s", body, w.Code, w.Body.String())
		}
	}
}

func TestForgotPassword_RateLimit(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewAuthHandler(d, "test-secret")

	body := `{"username":"nobody"}`
	var lastCode int
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ForgotPassword(w, req)
		lastCode = w.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on 6th attempt, got %d", lastCode)
	}
}

func TestForgotPassword_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewAuthHandler(d, "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader([]byte(`bad`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ForgotPassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestForgotPassword_MissingUsername(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewAuthHandler(d, "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/forgot-password", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ForgotPassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestResetPassword_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewAuthHandler(d, "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader([]byte(`bad`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ResetPassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestResetPassword_MissingToken(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewAuthHandler(d, "test-secret")

	req := httptest.NewRequest(http.MethodPost, "/api/auth/reset-password", bytes.NewReader([]byte(`{"new_password":"longenough"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ResetPassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
