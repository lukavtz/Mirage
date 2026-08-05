package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

func TestSessions_MarkViewed_Success(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewSessionsHandler(d, nil, db.ProviderSQLite)

	uid := createTestUser(t, d, "mvuser", "pass")
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', ?, datetime('now'))`, sid, uid); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/viewed", handler.MarkViewed)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/viewed", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessions_MarkViewed_NotFound(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewSessionsHandler(d, nil, db.ProviderSQLite)

	uid := createTestUser(t, d, "mvmiss", "pass")

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/viewed", handler.MarkViewed)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions/nonexistent/viewed", nil)
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessions_MarkViewed_Forbidden(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewSessionsHandler(d, nil, db.ProviderSQLite)

	owner := createTestUser(t, d, "mvboss", "pass")
	other := createTestUserWithRole(t, d, "mvtrespass", "pass", "user")
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', ?, datetime('now'))`, sid, owner); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/viewed", handler.MarkViewed)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/viewed", nil)
	claims := &auth.Claims{UserID: other, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessions_Unlock_NoClaims(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewSessionsHandler(d, nil, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/unlock", handler.Unlock)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions/abc/unlock", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSessions_Unlock_LockedByAnother(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewSessionsHandler(d, nil, db.ProviderSQLite)

	owner := createTestUser(t, d, "ulockowner", "pass")
	other := createTestUserWithRole(t, d, "ulockother", "pass", "user")
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', ?, datetime('now'))`, sid, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO session_locks (session_id, locked_by) VALUES (?, ?)", sid, owner); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/unlock", handler.Unlock)

	// Other user owns nothing; try to unlock -> 403 (fails ownsSession first)
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/unlock", nil)
	claims := &auth.Claims{UserID: other, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}
