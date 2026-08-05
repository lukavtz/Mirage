package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
)

func TestRequireRole_NoClaims(t *testing.T) {
	handler := middleware.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestRequireRole_MatchingRole(t *testing.T) {
	var called bool
	handler := middleware.RequireRole("admin", "worker")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := middleware.ContextWithClaims(req.Context(), &auth.Claims{Role: "worker"})
	handler.ServeHTTP(rec, req.WithContext(ctx))
	if !called {
		t.Error("next handler should be called for matching role")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireRole_Denied(t *testing.T) {
	handler := middleware.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := middleware.ContextWithClaims(req.Context(), &auth.Claims{Role: "worker"})
	handler.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}
