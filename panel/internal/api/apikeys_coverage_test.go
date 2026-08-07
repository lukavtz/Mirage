package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestGenerateAPIKey(t *testing.T) {
	raw, hash := generateAPIKey()
	if len(raw) != 64 {
		t.Errorf("raw key length = %d, want 64", len(raw))
	}
	if len(hash) != 64 {
		t.Errorf("hash length = %d, want 64", len(hash))
	}
}

func TestAPIKeyCreate_Success(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "apikey-create-user", "password123")
	handler := NewAPIKeyHandler(d)

	body := `{"name":"test-key","scope":"write","rate_limit":200}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.Create(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp APIKeyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Name != "test-key" {
		t.Errorf("name = %q, want test-key", resp.Name)
	}
	if resp.Scope != "write" {
		t.Errorf("scope = %q, want write", resp.Scope)
	}
	if resp.RateLimit != 200 {
		t.Errorf("rate_limit = %d, want 200", resp.RateLimit)
	}
	if len(resp.Key) != 64 {
		t.Errorf("key length = %d, want 64", len(resp.Key))
	}
	if resp.ID == "" {
		t.Error("id is empty")
	}
}

func TestAPIKeyCreate_EmptyName(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "apikey-empty-name", "password123")
	handler := NewAPIKeyHandler(d)

	body := `{"name":"","scope":"read","rate_limit":100}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeyCreate_NoAuth(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := NewAPIKeyHandler(d)

	body := `{"name":"test-key"}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Create(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeyList_Success(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "apikey-list-user", "password123")
	handler := NewAPIKeyHandler(d)

	// Create a key first so there's something to list
	body := `{"name":"listable-key","scope":"read","rate_limit":50}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	handler.Create(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("create failed: %d: %s", w.Code, w.Body.String())
	}

	// List keys
	listReq := httptest.NewRequest(http.MethodGet, "/", nil)
	listReq = listReq.WithContext(middleware.ContextWithClaims(listReq.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	listW := httptest.NewRecorder()
	handler.List(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", listW.Code, listW.Body.String())
	}
	var listResp map[string]any
	if err := json.Unmarshal(listW.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keys, ok := listResp["keys"].([]any)
	if !ok {
		t.Fatalf("keys is not an array, got %T", listResp["keys"])
	}
	if len(keys) != 1 {
		t.Errorf("expected 1 key, got %d", len(keys))
	}
}

func TestAPIKeyList_NoAuth(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := NewAPIKeyHandler(d)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.List(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeyDelete_Success(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "apikey-del-user", "password123")
	handler := NewAPIKeyHandler(d)

	// Create a key to delete
	keyID := uuid.New().String()
	rawKey, keyHash := generateAPIKey()
	_, err := d.Exec("INSERT INTO api_keys (id, user_id, name, key_hash, scope, rate_limit) VALUES ($1, $2, $3, $4, $5, $6)",
		keyID, uid, "delete-me", keyHash, "read", 100)
	if err != nil {
		t.Fatalf("insert key: %v", err)
	}
	_ = rawKey

	r := chi.NewRouter()
	r.Delete("/api/keys/{id}", handler.Delete)
	req := httptest.NewRequest(http.MethodDelete, "/api/keys/"+keyID, nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["message"] != "API key revoked" {
		t.Errorf("message = %q, want API key revoked", resp["message"])
	}
}

func TestAPIKeyDelete_NotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	uid := createTestUser(t, d, "apikey-del-notfound", "password123")
	handler := NewAPIKeyHandler(d)

	r := chi.NewRouter()
	r.Delete("/api/keys/{id}", handler.Delete)
	req := httptest.NewRequest(http.MethodDelete, "/api/keys/"+uuid.New().String(), nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKeyDelete_NoAuth(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := NewAPIKeyHandler(d)

	r := chi.NewRouter()
	r.Delete("/api/keys/{id}", handler.Delete)
	req := httptest.NewRequest(http.MethodDelete, "/api/keys/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}
