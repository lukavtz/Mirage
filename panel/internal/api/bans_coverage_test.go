package api_test

import (
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

func newBanTestHandler(t *testing.T) (*api.BanHandler, *chi.Mux) {
	t.Helper()
	d := openTestDB(t)
	handler := api.NewBanHandler(d, db.ProviderSQLite)
	r := chi.NewRouter()
	r.Delete("/api/bans/{id}", handler.Delete)
	return handler, r
}

func banAdminRequest(t *testing.T, d interface{}) {
	t.Helper()
}

func TestBans_ListEmpty(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewBanHandler(d, db.ProviderSQLite)

	req := httptest.NewRequest(http.MethodGet, "/api/bans", nil)
	w := httptest.NewRecorder()
	handler.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("expected empty array, got %s", w.Body.String())
	}
}

func TestBans_CreateIP(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewBanHandler(d, db.ProviderSQLite)
	uid := createTestUser(t, d, "banadmin", "pass")

	body := `{"ip":"203.0.113.10","reason":"spam"}`
	req := httptest.NewRequest(http.MethodPost, "/api/bans", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	handler.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["id"] == "" {
		t.Error("expected ban id")
	}
	if resp["ip"] != "203.0.113.10" {
		t.Errorf("ip = %v, want %q", resp["ip"], "203.0.113.10")
	}
	if resp["reason"] != "spam" {
		t.Errorf("reason = %v, want %q", resp["reason"], "spam")
	}
	if resp["created_by"] != uid {
		t.Errorf("created_by = %v, want %q", resp["created_by"], uid)
	}
	if resp["banned_at"] == "" {
		t.Error("expected banned_at")
	}
}

func TestBans_CreateHWID(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewBanHandler(d, db.ProviderSQLite)
	uid := createTestUser(t, d, "banadmin2", "pass")

	body := `{"hwid":"HWID-ABC-123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/bans", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	handler.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["id"] == "" {
		t.Error("expected ban id")
	}
	if resp["reason"] != "banned by admin" {
		t.Errorf("default reason = %v, want %q", resp["reason"], "banned by admin")
	}
}

func TestBans_CreateEmptyIPAndHWID(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewBanHandler(d, db.ProviderSQLite)
	uid := createTestUser(t, d, "banadmin3", "pass")

	body := `{"reason":"nothing"}`
	req := httptest.NewRequest(http.MethodPost, "/api/bans", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	handler.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestBans_CreateInvalidJSON(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewBanHandler(d, db.ProviderSQLite)
	uid := createTestUser(t, d, "banadmin4", "pass")

	body := `{"ip":`
	req := httptest.NewRequest(http.MethodPost, "/api/bans", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	handler.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestBans_CreateNoClaims(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewBanHandler(d, db.ProviderSQLite)

	body := `{"ip":"198.51.100.5"}`
	req := httptest.NewRequest(http.MethodPost, "/api/bans", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Create(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestBans_DeleteAfterCreate(t *testing.T) {
	d := openTestDB(t)
	handler, r := newBanTestHandler(t)
	uid := createTestUser(t, d, "banadmin5", "pass")

	createBody := `{"ip":"203.0.113.50"}`
	creq := httptest.NewRequest(http.MethodPost, "/api/bans", strings.NewReader(createBody))
	creq.Header.Set("Content-Type", "application/json")
	creq = creq.WithContext(middleware.ContextWithClaims(creq.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	cw := httptest.NewRecorder()
	handler.Create(cw, creq)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d: %s", cw.Code, cw.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(cw.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	banID := created["id"].(string)

	req := httptest.NewRequest(http.MethodDelete, "/api/bans/"+banID, nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["message"] == "" {
		t.Error("expected message")
	}
}

func TestBans_DeleteNonexistent(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewBanHandler(d, db.ProviderSQLite)
	r := chi.NewRouter()
	r.Delete("/api/bans/{id}", handler.Delete)
	uid := createTestUser(t, d, "banadmin6", "pass")

	req := httptest.NewRequest(http.MethodDelete, "/api/bans/does-not-exist", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["error"] == "" {
		t.Error("expected error message")
	}
}

func TestBans_DeleteNoClaims(t *testing.T) {
	d := openTestDB(t)
	handler, r := newBanTestHandler(t)
	uid := createTestUser(t, d, "banadmin7", "pass")

	createBody := `{"ip":"203.0.113.77"}`
	creq := httptest.NewRequest(http.MethodPost, "/api/bans", strings.NewReader(createBody))
	creq.Header.Set("Content-Type", "application/json")
	creq = creq.WithContext(middleware.ContextWithClaims(creq.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	cw := httptest.NewRecorder()
	handler.Create(cw, creq)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d: %s", cw.Code, cw.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(cw.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	banID := created["id"].(string)

	req := httptest.NewRequest(http.MethodDelete, "/api/bans/"+banID, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBans_ListShowsCreated(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewBanHandler(d, db.ProviderSQLite)
	uid := createTestUser(t, d, "banadmin8", "pass")

	createBody := `{"ip":"203.0.113.99","reason":"manual"}`
	creq := httptest.NewRequest(http.MethodPost, "/api/bans", strings.NewReader(createBody))
	creq.Header.Set("Content-Type", "application/json")
	creq = creq.WithContext(middleware.ContextWithClaims(creq.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	cw := httptest.NewRecorder()
	handler.Create(cw, creq)
	if cw.Code != http.StatusCreated {
		t.Fatalf("setup: expected 201, got %d: %s", cw.Code, cw.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/bans", nil)
	w := httptest.NewRecorder()
	handler.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var bans []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &bans); err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 {
		t.Fatalf("expected 1 ban, got %d", len(bans))
	}
	if bans[0]["ip"] != "203.0.113.99" {
		t.Errorf("ip = %v, want %q", bans[0]["ip"], "203.0.113.99")
	}
	if bans[0]["reason"] != "manual" {
		t.Errorf("reason = %v, want %q", bans[0]["reason"], "manual")
	}
}
