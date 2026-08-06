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

func TestRegisterEdgeCases(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewUsersHandler(d, "test-secret")
	r := chi.NewRouter()
	r.Post("/api/auth/register", h.Register)

	// missing fields
	for _, body := range []string{`{}`, `{"username":"x"}`, `{"invite_code":"x"}`} {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("register %s: expected 400, got %d", body, w.Code)
		}
	}
}

func TestChatDelete(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewChatHandler(d, nil)
	r := chi.NewRouter()
	r.Delete("/api/chat/{id}", h.Delete)
	r.Post("/api/chat", h.Send)
	r.Get("/api/chat", h.List)

	uid := createTestUser(t, d, "chatuser", "pass")
	// send
	req := httptest.NewRequest(http.MethodPost, "/api/chat", bytes.NewReader([]byte(`{"message":"hi"}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("chat send: expected 201, got %d", w.Code)
	}
	var sent struct {
		ID string `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &sent)

	// delete
	req = httptest.NewRequest(http.MethodDelete, "/api/chat/"+sent.ID, nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("chat delete: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestMarketplaceStartTrial(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewMarketplaceHandler(d)
	r := chi.NewRouter()
	r.Post("/api/marketplace/trial", h.StartTrial)

	uid := "trial-user"
	req := httptest.NewRequest(http.MethodPost, "/api/marketplace/trial", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("trial1: expected 200/201, got %d: %s", w.Code, w.Body.String())
	}
	// duplicate
	req = httptest.NewRequest(http.MethodPost, "/api/marketplace/trial", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("trial2: expected 400, got %d", w.Code)
	}
}

func TestExportNetscapeFull(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewExportHandler(d)
	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/export", h.ExportSession)

	uid := "ex-user"
	sid := uuid.New().String()
	d.Exec("INSERT INTO sessions (id, build_id, owner_id) VALUES ($1, $2, $3)", sid, "b1", uid)
	d.Exec("INSERT INTO passwords (id, session_id, url, username, password_value, browser) VALUES ($1, $2, $3, $4, $5, $6)",
		uuid.New().String(), sid, "https://example.com", "alice", "secret", "chrome")

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"/export?format=netscape", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("export: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if w.Body.Len() == 0 {
		t.Fatal("export: empty body")
	}

	// missing session → 404
	req = httptest.NewRequest(http.MethodGet, "/api/sessions/nope/export?format=netscape", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("export missing: expected 404, got %d", w.Code)
	}
}

var _ = uuid.New
