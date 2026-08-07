package api_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/testutil"
)

func setupBotHandler(t *testing.T) (*api.TelegramBotHandler, *sql.DB) {
	t.Helper()
	d := testutil.OpenTestDB(t)
	return api.NewTelegramBotHandler(d), d
}

func insertTestBot(t *testing.T, db *sql.DB) string {
	t.Helper()
	id := uuid.New().String()
	_, err := db.Exec(
		`INSERT INTO telegram_bots (id, name, token, chat_id, tier, is_active) VALUES ($1, $2, $3, $4, $5, TRUE)`,
		id, "test-bot", "test:token", "12345", "basic",
	)
	if err != nil {
		t.Fatalf("insert bot: %v", err)
	}

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM telegram_bots").Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	t.Logf("bots in DB after insert: %d", count)

	return id
}

func TestBot_ListEmpty(t *testing.T) {
	handler, _ := setupBotHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/bots", nil)
	w := httptest.NewRecorder()
	handler.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var bots []any
	if err := json.Unmarshal(w.Body.Bytes(), &bots); err != nil {
		t.Fatal(err)
	}
	if len(bots) != 0 {
		t.Errorf("expected empty list, got %d", len(bots))
	}
}

func TestBot_ListWithData(t *testing.T) {
	handler, d := setupBotHandler(t)
	insertTestBot(t, d)

	req := httptest.NewRequest(http.MethodGet, "/api/bots", nil)
	w := httptest.NewRecorder()
	handler.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var bots []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &bots); err != nil {
		t.Fatal(err)
	}
	t.Logf("handler returned %d bots", len(bots))
	if len(bots) != 1 {
		t.Fatalf("expected 1 bot, got %d", len(bots))
	}
	if bots[0]["name"] != "test-bot" {
		t.Errorf("name = %v, want test-bot", bots[0]["name"])
	}
}

func TestBot_Update(t *testing.T) {
	handler, d := setupBotHandler(t)
	botID := insertTestBot(t, d)

	body := `{"is_active":false}`
	r := chi.NewRouter()
	r.Put("/api/bots/{id}", handler.Update)
	req := httptest.NewRequest(http.MethodPut, "/api/bots/"+botID, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var isActive bool
	d.QueryRow("SELECT is_active FROM telegram_bots WHERE id = $1", botID).Scan(&isActive)
	if isActive {
		t.Error("expected is_active=false")
	}
}

func TestBot_Delete(t *testing.T) {
	handler, d := setupBotHandler(t)
	botID := insertTestBot(t, d)

	r := chi.NewRouter()
	r.Delete("/api/bots/{id}", handler.Delete)
	req := httptest.NewRequest(http.MethodDelete, "/api/bots/"+botID, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM telegram_bots WHERE id = $1", botID).Scan(&count)
	if count != 0 {
		t.Error("expected bot to be deleted")
	}
}

func TestBot_UpdateNotFound(t *testing.T) {
	handler, _ := setupBotHandler(t)

	body := `{"is_active":false}`
	r := chi.NewRouter()
	r.Put("/api/bots/{id}", handler.Update)
	req := httptest.NewRequest(http.MethodPut, "/api/bots/nonexistent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", w.Code)
	}
}

func TestBot_Filters(t *testing.T) {
	handler, d := setupBotHandler(t)
	botID := insertTestBot(t, d)

	r := chi.NewRouter()
	r.Post("/api/bots/{id}/filters", handler.CreateFilter)

	body := `{"filter_type":"country","filter_value":"US"}`
	req := httptest.NewRequest(http.MethodPost, "/api/bots/"+botID+"/filters", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	filterID := resp["id"].(string)

	var count int
	d.QueryRow("SELECT COUNT(*) FROM bot_filters WHERE id = $1", filterID).Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 filter, got %d", count)
	}

	listR := chi.NewRouter()
	listR.Get("/api/bots/{id}/filters", handler.ListFilters)
	listReq := httptest.NewRequest(http.MethodGet, "/api/bots/"+botID+"/filters", nil)
	listW := httptest.NewRecorder()
	listR.ServeHTTP(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listW.Code)
	}

	var filters []map[string]any
	if err := json.Unmarshal(listW.Body.Bytes(), &filters); err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatalf("expected 1 filter, got %d", len(filters))
	}
	if filters[0]["filter_type"] != "country" {
		t.Errorf("filter_type = %v, want country", filters[0]["filter_type"])
	}

	delR := chi.NewRouter()
	delR.Delete("/api/bots/{id}/filters/{filter_id}", handler.DeleteFilter)
	delReq := httptest.NewRequest(http.MethodDelete, "/api/bots/"+botID+"/filters/"+filterID, nil)
	delW := httptest.NewRecorder()
	delR.ServeHTTP(delW, delReq)

	if delW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", delW.Code)
	}

	d.QueryRow("SELECT COUNT(*) FROM bot_filters WHERE id = $1", filterID).Scan(&count)
	if count != 0 {
		t.Error("expected filter to be deleted")
	}
}

func TestBot_InvalidFilterType(t *testing.T) {
	handler, d := setupBotHandler(t)
	botID := insertTestBot(t, d)

	body := `{"filter_type":"invalid","filter_value":"x"}`
	r := chi.NewRouter()
	r.Post("/api/bots/{id}/filters", handler.CreateFilter)
	req := httptest.NewRequest(http.MethodPost, "/api/bots/"+botID+"/filters", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid filter type, got %d", w.Code)
	}
}
