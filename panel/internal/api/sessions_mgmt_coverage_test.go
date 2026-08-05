package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

func TestParseUserAgent(t *testing.T) {
	cases := []struct {
		ua       string
		os, brow string
	}{
		{"", "Unknown", "Unknown"},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0", "Windows", "Chrome"},
		{"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/121.0", "macOS", "Firefox"},
		{"Mozilla/5.0 (X11; Linux x86_64) Safari/605.1.15", "Linux", "Safari"},
		{"Mozilla/5.0 (Android 14; Mobile) Edg/120.0", "Android", "Edge"},
		{"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) OPR/80.0", "iOS", "Opera"},
		{"some-random-ua", "Unknown", "Unknown"},
		{"Mozilla/5.0 (Windows) Opera/100.0", "Windows", "Opera"},
	}
	for _, tc := range cases {
		os, brow := api.ParseUserAgent(tc.ua)
		if os != tc.os || brow != tc.brow {
			t.Errorf("ParseUserAgent(%q) = (%q,%q), want (%q,%q)", tc.ua, os, brow, tc.os, tc.brow)
		}
	}
}

func TestSessionMgmt_List(t *testing.T) {
	d := openTestDB(t)
	h := api.NewSessionMgmtHandler(d, db.ProviderSQLite)
	r := chi.NewRouter()
	r.Get("/api/auth/sessions", h.List)
	r.Delete("/api/auth/sessions/{id}", h.Terminate)
	r.Delete("/api/auth/sessions", h.TerminateAll)

	uid := "sm-user"
	if _, err := d.Exec("INSERT INTO auth_sessions (id, user_id, token_hash, device, os, browser, ip, last_active_at, created_at) VALUES (?, ?, 'hash', 'Chrome', 'Windows', 'Chrome', '1.2.3.4', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
		"sess1", uid, "hash"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/auth/sessions", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	jsonDecode(t, w.Body.Bytes(), &resp)
	sessions := resp["sessions"].([]any)
	if len(sessions) != 1 {
		t.Fatalf("list: expected 1 session, got %d", len(sessions))
	}

	// no auth
	req = httptest.NewRequest(http.MethodGet, "/api/auth/sessions", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth list: expected 401, got %d", w.Code)
	}
}

func TestSessionMgmt_Terminate(t *testing.T) {
	d := openTestDB(t)
	h := api.NewSessionMgmtHandler(d, db.ProviderSQLite)
	r := chi.NewRouter()
	r.Delete("/api/auth/sessions/{id}", h.Terminate)

	uid := "sm-user2"
	if _, err := d.Exec("INSERT INTO auth_sessions (id, user_id, token_hash) VALUES (?, ?, ?)", "sessA", uid, "hash"); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/sessA", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("terminate: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// nonexistent
	req = httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/nope", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("terminate missing: expected 404, got %d", w.Code)
	}

	// no auth
	req = httptest.NewRequest(http.MethodDelete, "/api/auth/sessions/sessA", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth terminate: expected 401, got %d", w.Code)
	}
}

func TestSessionMgmt_TerminateAll(t *testing.T) {
	d := openTestDB(t)
	h := api.NewSessionMgmtHandler(d, db.ProviderSQLite)
	r := chi.NewRouter()
	r.Delete("/api/auth/sessions", h.TerminateAll)

	uid := "sm-user3"
	for _, sid := range []string{"s1", "s2", "s3"} {
		if _, err := d.Exec("INSERT INTO auth_sessions (id, user_id, token_hash) VALUES (?, ?, ?)", sid, uid, "hash"); err != nil {
			t.Fatal(err)
		}
	}

	// with current session id: deletes others
	req := httptest.NewRequest(http.MethodDelete, "/api/auth/sessions", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user", SessionID: "s1"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("terminate all: expected 200, got %d", w.Code)
	}
	var cnt int
	d.QueryRow("SELECT COUNT(*) FROM auth_sessions WHERE user_id = ?", uid).Scan(&cnt)
	if cnt != 1 {
		t.Fatalf("terminate all: expected 1 remaining (current), got %d", cnt)
	}

	// without session id: deletes everything
	req = httptest.NewRequest(http.MethodDelete, "/api/auth/sessions", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("terminate all 2: expected 200, got %d", w.Code)
	}
	d.QueryRow("SELECT COUNT(*) FROM auth_sessions WHERE user_id = ?", uid).Scan(&cnt)
	if cnt != 0 {
		t.Fatalf("terminate all 2: expected 0 remaining, got %d", cnt)
	}
}

func jsonDecode(t *testing.T, data []byte, out any) {
	t.Helper()
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatalf("json decode: %v; body=%s", err, data)
	}
}
