package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

func TestUsers_CreateInvite_Defaults(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewUsersHandler(d, "test-secret", db.ProviderSQLite)

	uid := createTestUser(t, d, "invdefault", "pass")

	r := chi.NewRouter()
	r.Post("/api/users/invite", handler.CreateInvite)

	req := httptest.NewRequest(http.MethodPost, "/api/users/invite", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["role"] != "worker" {
		t.Errorf("role = %v, want worker (default)", resp["role"])
	}
	if resp["tier"] != "starter" {
		t.Errorf("tier = %v, want starter (default)", resp["tier"])
	}
	if resp["max_uses"] != float64(1) {
		t.Errorf("max_uses = %v, want 1 (default)", resp["max_uses"])
	}
	if resp["expires_at"] != nil {
		t.Errorf("expires_at = %v, want nil", resp["expires_at"])
	}
}

func TestUsers_CreateInvite_AllFields(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewUsersHandler(d, "test-secret", db.ProviderSQLite)

	uid := createTestUser(t, d, "invfull", "pass")

	r := chi.NewRouter()
	r.Post("/api/users/invite", handler.CreateInvite)

	body := `{"role":"admin","tier":"pro","max_uses":3,"duration":"48h"}`
	req := httptest.NewRequest(http.MethodPost, "/api/users/invite", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["role"] != "admin" {
		t.Errorf("role = %v, want admin", resp["role"])
	}
	if resp["tier"] != "pro" {
		t.Errorf("tier = %v, want pro", resp["tier"])
	}
	if resp["max_uses"] != float64(3) {
		t.Errorf("max_uses = %v, want 3", resp["max_uses"])
	}
	if resp["expires_at"] == nil {
		t.Error("expected expires_at with duration")
	}
}

func TestUsers_CreateInvite_InvalidJSON(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewUsersHandler(d, "test-secret", db.ProviderSQLite)

	uid := createTestUser(t, d, "invbad", "pass")

	r := chi.NewRouter()
	r.Post("/api/users/invite", handler.CreateInvite)

	req := httptest.NewRequest(http.MethodPost, "/api/users/invite", bytes.NewReader([]byte(`bad`)))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestUsers_CreateInvite_Unauthorized(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewUsersHandler(d, "test-secret", db.ProviderSQLite)

	r := chi.NewRouter()
	r.Post("/api/users/invite", handler.CreateInvite)

	req := httptest.NewRequest(http.MethodPost, "/api/users/invite", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}
