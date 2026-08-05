package api_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

func insertRestoreSession(t *testing.T, d *sql.DB, ownerID string) string {
	t.Helper()
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', ?, datetime('now'))`, sid, ownerID); err != nil {
		t.Fatal(err)
	}
	return sid
}

func TestRestore_UploadCookies_NoClaims(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Post("/api/restore/upload", handler.UploadCookies)

	req := httptest.NewRequest(http.MethodPost, "/api/restore/upload", strings.NewReader(`{"session_id":"x","cookies":[]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRestore_UploadCookies_InvalidJSON(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "upjson", "pass")

	r := chi.NewRouter()
	r.Post("/api/restore/upload", handler.UploadCookies)

	req := httptest.NewRequest(http.MethodPost, "/api/restore/upload", bytes.NewReader([]byte(`bad`)))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRestore_UploadCookies_MissingFields(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "upmiss", "pass")

	r := chi.NewRouter()
	r.Post("/api/restore/upload", handler.UploadCookies)

	cases := []string{
		`{"cookies":[{"domain":"d","name":"n","value":"v","path":"/"}]}`, // no session_id
		`{"session_id":"sid","cookies":[]}`,                              // no cookies
	}
	for _, body := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/restore/upload", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		claims := &auth.Claims{UserID: uid, Role: "admin"}
		req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %s: expected 400, got %d: %s", body, w.Code, w.Body.String())
		}
	}
}

func TestRestore_UploadCookies_Forbidden(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	owner := createTestUser(t, d, "reowner", "pass")
	other := createTestUser(t, d, "reother", "pass")
	sid := insertRestoreSession(t, d, owner)

	r := chi.NewRouter()
	r.Post("/api/restore/upload", handler.UploadCookies)

	body := `{"session_id":"` + sid + `","cookies":[{"domain":"d","name":"n","value":"v","path":"/"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/restore/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: other, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRestore_UploadCookies_Success(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "upsuccess", "pass")
	sid := insertRestoreSession(t, d, uid)

	r := chi.NewRouter()
	r.Post("/api/restore/upload", handler.UploadCookies)

	body := `{"session_id":"` + sid + `","cookies":[{"domain":"example.com","name":"sid","value":"abc","path":"/"}],"proxy_config":{"type":"socks5","host":"127.0.0.1","port":1080}}`
	req := httptest.NewRequest(http.MethodPost, "/api/restore/upload", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["id"] == "" {
		t.Fatal("expected restore session id")
	}
	if resp["status"] != "processing" {
		t.Errorf("status = %q, want processing", resp["status"])
	}

	// processRestore runs async; it should finalize status (no proxy host -> completed)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var status string
		if err := d.QueryRow("SELECT status FROM restore_sessions WHERE id = ?", resp["id"]).Scan(&status); err == nil && status != "processing" {
			if status != "completed" && status != "failed" {
				t.Fatalf("unexpected final status %q", status)
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("restore session did not finalize within timeout")
}

func TestRestore_ListSessions_NoClaims(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Get("/api/restore/sessions", handler.ListSessions)

	req := httptest.NewRequest(http.MethodGet, "/api/restore/sessions", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRestore_ListSessions_UserAndAdmin(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	uid := createTestUserWithRole(t, d, "rsuser", "pass", "user")
	admin := createTestUser(t, d, "rsadmin", "pass")

	// Seed a restore session directly
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := d.Exec(
		`INSERT INTO restore_sessions (id, user_id, session_id, cookies_json, proxy_config, status, access_token, error, created_at, updated_at)
		 VALUES (?, ?, 'sid1', '[{}]', '', 'completed', '', '', ?, ?)`,
		uuid.New().String(), uid, now, now,
	); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/restore/sessions", handler.ListSessions)

	// User sees their own
	req := httptest.NewRequest(http.MethodGet, "/api/restore/sessions", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var sessions []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Errorf("user: expected 1 session, got %d", len(sessions))
	}

	// Admin sees all
	req2 := httptest.NewRequest(http.MethodGet, "/api/restore/sessions", nil)
	adminClaims := &auth.Claims{UserID: admin, Role: "admin"}
	req2 = req2.WithContext(middleware.ContextWithClaims(req2.Context(), adminClaims))
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w2.Code, w2.Body.String())
	}
	var sessions2 []map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &sessions2); err != nil {
		t.Fatal(err)
	}
	if len(sessions2) != 1 {
		t.Errorf("admin: expected 1 session, got %d", len(sessions2))
	}
}

func TestRestore_SessionStatus(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	uid := createTestUserWithRole(t, d, "rsstat", "pass", "user")
	other := createTestUser(t, d, "rsstat2", "pass")

	rsID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := d.Exec(
		`INSERT INTO restore_sessions (id, user_id, session_id, cookies_json, proxy_config, status, access_token, error, created_at, updated_at)
		 VALUES (?, ?, 'sid1', '[{}]', '', 'completed', 'tok123', '', ?, ?)`,
		rsID, uid, now, now,
	); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/restore/sessions/{id}", handler.SessionStatus)

	// Owner can view (token masked for non-admin)
	req := httptest.NewRequest(http.MethodGet, "/api/restore/sessions/"+rsID, nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "completed" {
		t.Errorf("status = %v, want completed", resp["status"])
	}
	if tok, exists := resp["access_token"]; exists && tok != "" {
		t.Errorf("non-admin should not see access_token, got %v", tok)
	}

	// Other non-admin user -> 403
	req2 := httptest.NewRequest(http.MethodGet, "/api/restore/sessions/"+rsID, nil)
	otherClaims := &auth.Claims{UserID: other, Role: "user"}
	req2 = req2.WithContext(middleware.ContextWithClaims(req2.Context(), otherClaims))
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w2.Code, w2.Body.String())
	}

	// Admin sees access token
	adminClaims := &auth.Claims{UserID: other, Role: "admin"}
	req3 := httptest.NewRequest(http.MethodGet, "/api/restore/sessions/"+rsID, nil)
	req3 = req3.WithContext(middleware.ContextWithClaims(req3.Context(), adminClaims))
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("admin: expected 200, got %d: %s", w3.Code, w3.Body.String())
	}
	var resp3 map[string]any
	if err := json.Unmarshal(w3.Body.Bytes(), &resp3); err != nil {
		t.Fatal(err)
	}
	if resp3["access_token"] != "tok123" {
		t.Errorf("admin access_token = %v, want tok123", resp3["access_token"])
	}

	// Not found
	req4 := httptest.NewRequest(http.MethodGet, "/api/restore/sessions/nonexistent", nil)
	req4 = req4.WithContext(middleware.ContextWithClaims(req4.Context(), adminClaims))
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w4.Code, w4.Body.String())
	}
}

func TestRestore_SessionStatus_NoClaims(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Get("/api/restore/sessions/{id}", handler.SessionStatus)

	req := httptest.NewRequest(http.MethodGet, "/api/restore/sessions/abc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRestore_NoProxy_Extra(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "noproxy", "pass")
	sid := insertRestoreSession(t, d, uid)

	body := `{"session_id":"` + sid + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.Restore(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRestore_SessionNotFound(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "nosess", "pass")

	body := `{"session_id":"missing","proxy":"socks5://127.0.0.1:1080"}`
	req := httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.Restore(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRestore_Forbidden(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	owner := createTestUser(t, d, "resowner", "pass")
	other := createTestUserWithRole(t, d, "resother", "pass", "user")
	sid := insertRestoreSession(t, d, owner)

	body := `{"session_id":"` + sid + `","proxy":"socks5://127.0.0.1:1080"}`
	req := httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: other, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.Restore(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRestore_SuccessWithCookies(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "ressuccess", "pass")
	sid := insertRestoreSession(t, d, uid)

	if _, err := d.Exec(
		`INSERT INTO cookies (id, session_id, name, domain, value, path) VALUES (?, ?, 'sid', 'example.com', 'abc', '/')`,
		uuid.New().String(), sid,
	); err != nil {
		t.Fatal(err)
	}

	body := `{"session_id":"` + sid + `","proxy":"socks5://127.0.0.1:1080"}`
	req := httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.Restore(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	count, _ := resp["count"].(float64)
	if count != 1 {
		t.Errorf("count = %v, want 1", count)
	}
	proxy, _ := resp["proxy"].(string)
	if proxy != "socks5://127.0.0.1:1080" {
		t.Errorf("proxy = %q, want socks5://127.0.0.1:1080", proxy)
	}
}

func TestRestore_SuccessWithProxyConfig(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewRestoreHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "resproxycfg", "pass")
	sid := insertRestoreSession(t, d, uid)

	body := `{"session_id":"` + sid + `","proxy_config":{"type":"socks5","host":"127.0.0.1","port":1080}}`
	req := httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.Restore(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["session_id"] != sid {
		t.Errorf("session_id = %v, want %q", resp["session_id"], sid)
	}
}
