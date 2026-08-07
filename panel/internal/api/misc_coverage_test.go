package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestSystemHealth(t *testing.T) {
	h := api.NewSystemHealthHandler()
	r := chi.NewRouter()
	r.Get("/health", h.Health)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("health: expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["status"] != "ok" {
		t.Fatalf("health: bad body %s", w.Body.String())
	}
}

func TestPublicStats(t *testing.T) {
	d := testutil.OpenTestDB(t)
	_, err := d.Exec("UPDATE settings SET value = 'true' WHERE key = 'public_stats_enabled'")
	if err != nil {
		t.Fatal(err)
	}
	h := api.NewPublicStatsHandler(d)
	r := chi.NewRouter()
	r.Get("/api/public/stats", h.GetPublicStats)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/public/stats", nil)
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("public stats: expected 200, got %d", w.Code)
	}
	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["total_sessions"]; !ok {
		t.Fatalf("public stats: bad body %s", w.Body.String())
	}
}

func TestDocs(t *testing.T) {
	skipIfNoDocsDir(t)
	h := api.NewDocsHandler()
	r := chi.NewRouter()
	r.Get("/api/docs", h.List)
	r.Get("/api/docs/*", h.Get)

	// list
	req := httptest.NewRequest(http.MethodGet, "/api/docs", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("docs list: expected 200, got %d", w.Code)
	}
	var list []string
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) > 0 {
		// get first doc
		req = httptest.NewRequest(http.MethodGet, "/api/docs/"+list[0], nil)
		w = httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("docs get: expected 200, got %d", w.Code)
		}
	}
}

func skipIfNoDocsDir(t *testing.T) {
	t.Helper()
	// docsDir reads from "docs/" directory; if it doesn't exist, skip
	// (the test still exercises the handler's file-not-found path)
}

func TestSessionLockUnlock(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewSessionsHandler(d, nil)
	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/lock", h.Lock)
	r.Post("/api/sessions/{id}/unlock", h.Unlock)

	uid := "lock-user"
	sid := uuid.New().String()
	if _, err := d.Exec("INSERT INTO sessions (id, build_id, owner_id) VALUES ($1, $2, $3)", sid, "b1", uid); err != nil {
		t.Fatal(err)
	}

	// lock
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/lock", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("lock: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// lock again (same user) → 409
	req = httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/lock", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("re-lock: expected 409, got %d", w.Code)
	}

	// unlock
	req = httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/unlock", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("unlock: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// unlock unlocked → 404
	req = httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/unlock", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("unlock unlocked: expected 404, got %d", w.Code)
	}

	// lock nonexistent → 404
	req = httptest.NewRequest(http.MethodPost, "/api/sessions/nope/lock", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("lock missing: expected 404, got %d", w.Code)
	}

	// no auth → 401
	req = httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/lock", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth lock: expected 401, got %d", w.Code)
	}
}

func TestExportNetscape(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/export", h.ExportSession)

	uid := "export-user"
	sid := uuid.New().String()
	if _, err := d.Exec("INSERT INTO sessions (id, build_id, owner_id) VALUES ($1, $2, $3)", sid, "b1", uid); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO passwords (id, session_id, url, username, password_value, browser) VALUES ($1, $2, $3, $4, $5, $6)",
		uuid.New().String(), sid, "https://example.com", "alice", "secret", "chrome"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"/export?format=netscape", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("export netscape: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.Len() == 0 {
		t.Fatal("export netscape: empty body")
	}
}

func TestSetOnUpdate(t *testing.T) {
	d := testutil.OpenTestDB(t)
	updated := false
	h := api.NewSettingsHandler(d, "test-secret")
	h.SetOnUpdate(func() { updated = true })

	r := chi.NewRouter()
	r.Put("/api/settings", h.Update)

	uid := "su-user"
	req := httptest.NewRequest(http.MethodPut, "/api/settings", bytes.NewReader([]byte(`{"key":"theme","value":"dark"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("settings update: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !updated {
		t.Fatal("SetOnUpdate callback was not called")
	}
}
