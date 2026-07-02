package middleware_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/user/mirage-panel/internal/auth"
	"github.com/user/mirage-panel/internal/middleware"
)

func TestRequireRole_AdminAllowed(t *testing.T) {
	token, _, err := auth.GenerateToken("user-1", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}

	m := middleware.Auth("secret")
	rbac := middleware.RequireRole("admin")
	var called bool
	handler := m(rbac(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler should be called for admin role")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestRequireRole_WorkerDenied(t *testing.T) {
	token, _, err := auth.GenerateToken("user-2", "worker", "secret")
	if err != nil {
		t.Fatal(err)
	}

	m := middleware.Auth("secret")
	rbac := middleware.RequireRole("admin")
	handler := m(rbac(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for worker")
	})))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestRequireRole_MultipleRoles(t *testing.T) {
	t.Run("admin passes admin_or_worker", func(t *testing.T) {
		token, _, err := auth.GenerateToken("user-3", "admin", "secret")
		if err != nil {
			t.Fatal(err)
		}

		m := middleware.Auth("secret")
		rbac := middleware.RequireRole("admin", "worker")
		var called bool
		handler := m(rbac(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})))

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(rec, req)

		if !called {
			t.Error("admin should be allowed for admin_or_worker")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})

	t.Run("worker passes admin_or_worker", func(t *testing.T) {
		token, _, err := auth.GenerateToken("user-4", "worker", "secret")
		if err != nil {
			t.Fatal(err)
		}

		m := middleware.Auth("secret")
		rbac := middleware.RequireRole("admin", "worker")
		var called bool
		handler := m(rbac(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})))

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		handler.ServeHTTP(rec, req)

		if !called {
			t.Error("worker should be allowed for admin_or_worker")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("expected 200, got %d", rec.Code)
		}
	})
}

func TestRequireRole_NoClaims(t *testing.T) {
	rbac := middleware.RequireRole("admin")
	handler := rbac(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestRequireRole_UnknownRole(t *testing.T) {
	token, _, err := auth.GenerateToken("user-5", "viewer", "secret")
	if err != nil {
		t.Fatal(err)
	}

	m := middleware.Auth("secret")
	rbac := middleware.RequireRole("admin", "worker")
	handler := m(rbac(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for unknown role")
	})))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}
