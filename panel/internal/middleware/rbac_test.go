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

func TestRequirePermission_AdminHasAll(t *testing.T) {
	perms := []string{"view_sessions", "reveal_passwords", "lock_sessions", "download_logs", "manage_team", "manage_settings", "view_activity", "view_stats_link"}
	for _, perm := range perms {
		var called bool
		handler := middleware.RequirePermission(perm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := middleware.ContextWithClaims(req.Context(), &auth.Claims{Role: "admin"})
		handler.ServeHTTP(rec, req.WithContext(ctx))
		if !called {
			t.Errorf("admin should have permission %s", perm)
		}
	}
}

func TestRequirePermission_CheckerLimited(t *testing.T) {
	for _, perm := range []string{"view_sessions", "reveal_passwords", "lock_sessions"} {
		var called bool
		handler := middleware.RequirePermission(perm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
		}))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := middleware.ContextWithClaims(req.Context(), &auth.Claims{Role: "checker"})
		handler.ServeHTTP(rec, req.WithContext(ctx))
		if !called {
			t.Errorf("checker should have permission %s", perm)
		}
	}

	for _, perm := range []string{"manage_team", "manage_settings", "view_activity", "view_stats_link"} {
		handler := middleware.RequirePermission(perm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("checker should NOT have permission %s", perm)
		}))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := middleware.ContextWithClaims(req.Context(), &auth.Claims{Role: "checker"})
		handler.ServeHTTP(rec, req.WithContext(ctx))
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 for checker/%s, got %d", perm, rec.Code)
		}
	}
}

func TestRequirePermission_WorkerLimited(t *testing.T) {
	handler := middleware.RequirePermission("manage_team")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("worker should not have manage_team")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := middleware.ContextWithClaims(req.Context(), &auth.Claims{Role: "worker"})
	handler.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequirePermission_TrafferStatsOnly(t *testing.T) {
	var called bool
	handler := middleware.RequirePermission("view_stats_link")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := middleware.ContextWithClaims(req.Context(), &auth.Claims{Role: "traffer"})
	handler.ServeHTTP(rec, req.WithContext(ctx))
	if !called {
		t.Error("traffer should have view_stats_link")
	}

	handler2 := middleware.RequirePermission("view_sessions")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("traffer should not have view_sessions")
	}))
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx2 := middleware.ContextWithClaims(req2.Context(), &auth.Claims{Role: "traffer"})
	handler2.ServeHTTP(rec2, req2.WithContext(ctx2))
	if rec2.Code != http.StatusForbidden {
		t.Errorf("expected 403 for traffer/view_sessions, got %d", rec2.Code)
	}
}

func TestRequirePermission_UnknownRole(t *testing.T) {
	handler := middleware.RequirePermission("view_sessions")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("unknown role should be denied")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	ctx := middleware.ContextWithClaims(req.Context(), &auth.Claims{Role: "hacker"})
	handler.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestRequirePermission_NoClaims(t *testing.T) {
	handler := middleware.RequirePermission("view_sessions")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("should not be called without claims")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestHasPermission(t *testing.T) {
	if !middleware.HasPermission("admin", "manage_team") {
		t.Error("admin should have manage_team")
	}
	if !middleware.HasPermission("checker", "reveal_passwords") {
		t.Error("checker should have reveal_passwords")
	}
	if middleware.HasPermission("viewer", "reveal_passwords") {
		t.Error("viewer should NOT have reveal_passwords")
	}
	if !middleware.HasPermission("traffer", "view_stats_link") {
		t.Error("traffer should have view_stats_link")
	}
	if middleware.HasPermission("worker", "lock_sessions") {
		t.Error("worker should NOT have lock_sessions")
	}
	if middleware.HasPermission("nobody", "view_sessions") {
		t.Error("unknown role should have no permissions")
	}
}
