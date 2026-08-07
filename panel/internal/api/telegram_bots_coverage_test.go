package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func TestBot_Create_MissingFields(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewTelegramBotHandler(d)

	r := chi.NewRouter()
	r.Post("/api/telegram/bots", handler.Create)

	cases := []string{
		`{"name":"","token":"123:abc","chat_id":"1"}`,   // no name
		`{"name":"bot","token":"","chat_id":"1"}`,       // no token
		`{"name":"bot","token":"123:abc","chat_id":""}`, // no chat_id
	}
	for _, body := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/telegram/bots", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %s: expected 400, got %d: %s", body, w.Code, w.Body.String())
		}
	}
}

func TestBot_Create_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewTelegramBotHandler(d)

	r := chi.NewRouter()
	r.Post("/api/telegram/bots", handler.Create)

	req := httptest.NewRequest(http.MethodPost, "/api/telegram/bots", bytes.NewReader([]byte(`bad`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBot_Update_MissingID(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewTelegramBotHandler(d)

	// Call handler directly without URL param to hit the missing-id branch
	req := httptest.NewRequest(http.MethodPut, "/api/telegram/bots/", strings.NewReader(`{"is_active":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Update(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBot_Update_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewTelegramBotHandler(d)

	r := chi.NewRouter()
	r.Put("/api/telegram/bots/{id}", handler.Update)

	req := httptest.NewRequest(http.MethodPut, "/api/telegram/bots/some-id", bytes.NewReader([]byte(`bad`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBot_Update_MissingIsActive(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewTelegramBotHandler(d)

	r := chi.NewRouter()
	r.Put("/api/telegram/bots/{id}", handler.Update)

	req := httptest.NewRequest(http.MethodPut, "/api/telegram/bots/some-id", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBot_Update_NotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewTelegramBotHandler(d)

	r := chi.NewRouter()
	r.Put("/api/telegram/bots/{id}", handler.Update)

	req := httptest.NewRequest(http.MethodPut, "/api/telegram/bots/nonexistent", strings.NewReader(`{"is_active":true}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBot_Delete_MissingID(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewTelegramBotHandler(d)

	req := httptest.NewRequest(http.MethodDelete, "/api/telegram/bots/", nil)
	w := httptest.NewRecorder()
	handler.Delete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBot_Delete_NotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewTelegramBotHandler(d)

	r := chi.NewRouter()
	r.Delete("/api/telegram/bots/{id}", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/telegram/bots/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBot_Test_MissingID(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewTelegramBotHandler(d)

	req := httptest.NewRequest(http.MethodPost, "/api/telegram/bots//test", nil)
	w := httptest.NewRecorder()
	handler.Test(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBot_Test_NotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewTelegramBotHandler(d)

	r := chi.NewRouter()
	r.Post("/api/telegram/bots/{id}/test", handler.Test)

	req := httptest.NewRequest(http.MethodPost, "/api/telegram/bots/nonexistent/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBot_List_MasksTokenForNonAdmin(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewTelegramBotHandler(d)

	botID := uuid.New().String()
	if _, err := d.Exec(
		`INSERT INTO telegram_bots (id, name, token, chat_id, tier, is_active) VALUES ($1, 'maskbot', '1234567890:ABCDEFGHIJ', 'chat1', 'basic', TRUE)`,
		botID,
	); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/telegram/bots", handler.List)

	// Admin sees full token
	req := httptest.NewRequest(http.MethodGet, "/api/telegram/bots", nil)
	claims := &auth.Claims{UserID: uuid.New().String(), Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var bots []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &bots); err != nil {
		t.Fatal(err)
	}
	if len(bots) != 1 {
		t.Fatalf("expected 1 bot, got %d", len(bots))
	}
	if bots[0]["token"] != "1234567890:ABCDEFGHIJ" {
		t.Errorf("admin token = %v, want full token", bots[0]["token"])
	}

	// Non-admin sees masked token
	req2 := httptest.NewRequest(http.MethodGet, "/api/telegram/bots", nil)
	claims2 := &auth.Claims{UserID: uuid.New().String(), Role: "user"}
	req2 = req2.WithContext(middleware.ContextWithClaims(req2.Context(), claims2))
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	var bots2 []map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &bots2); err != nil {
		t.Fatal(err)
	}
	if len(bots2) != 1 {
		t.Fatalf("expected 1 bot, got %d", len(bots2))
	}
	tok, _ := bots2[0]["token"].(string)
	if tok == "1234567890:ABCDEFGHIJ" {
		t.Errorf("non-admin token should be masked, got %v", tok)
	}
	if !strings.Contains(tok, "****") {
		t.Errorf("non-admin token = %q, want masked with ****", tok)
	}
}
