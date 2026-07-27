package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/ws"
)

func TestChat_Send(t *testing.T) {
	d := openTestDB(t)
	hub := ws.NewHub()
	go hub.Run()
	handler := api.NewChatHandler(d, hub)

	uid := createTestUser(t, d, "chatuser", "pass")

	r := chi.NewRouter()
	r.Post("/api/chat/messages", handler.Send)

	body := `{"message":"hello world"}`
	req := httptest.NewRequest(http.MethodPost, "/api/chat/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["id"] == "" {
		t.Error("expected message id")
	}
	if resp["message"] != "hello world" {
		t.Errorf("message = %v, want %q", resp["message"], "hello world")
	}
	if resp["username"] != "chatuser" {
		t.Errorf("username = %v, want chatuser", resp["username"])
	}
}

func TestChat_SendEmptyMessage(t *testing.T) {
	d := openTestDB(t)
	hub := ws.NewHub()
	go hub.Run()
	handler := api.NewChatHandler(d, hub)

	uid := createTestUser(t, d, "chatuser2", "pass")

	r := chi.NewRouter()
	r.Post("/api/chat/messages", handler.Send)

	body := `{"message":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/chat/messages", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestChat_List(t *testing.T) {
	d := openTestDB(t)
	hub := ws.NewHub()
	go hub.Run()
	handler := api.NewChatHandler(d, hub)

	uid := createTestUser(t, d, "chatuser3", "pass")
	_, err := d.Exec(
		"INSERT INTO chat_messages (id, user_id, username, message, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
		uuid.New().String(), uid, "chatuser3", "test message",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/chat/messages", handler.List)

	q := url.Values{}
	q.Set("since", time.Now().UTC().Add(-1*time.Hour).Format(time.RFC3339))
	req := httptest.NewRequest(http.MethodGet, "/api/chat/messages?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &messages); err != nil {
		t.Fatal(err)
	}
	if len(messages) == 0 {
		t.Fatal("expected at least 1 message")
	}
	if messages[0]["message"] != "test message" {
		t.Errorf("message = %v, want %q", messages[0]["message"], "test message")
	}
}

func TestChat_ListEmpty(t *testing.T) {
	d := openTestDB(t)
	hub := ws.NewHub()
	go hub.Run()
	handler := api.NewChatHandler(d, hub)

	r := chi.NewRouter()
	r.Get("/api/chat/messages", handler.List)

	q := url.Values{}
	q.Set("since", time.Now().UTC().Add(1*time.Hour).Format(time.RFC3339))
	req := httptest.NewRequest(http.MethodGet, "/api/chat/messages?"+q.Encode(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var messages []any
	if err := json.Unmarshal(w.Body.Bytes(), &messages); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 0 {
		t.Errorf("expected empty list, got %d items", len(messages))
	}
}

func TestChat_Delete(t *testing.T) {
	d := openTestDB(t)
	hub := ws.NewHub()
	go hub.Run()
	handler := api.NewChatHandler(d, hub)

	uid := createTestUser(t, d, "chatuser4", "pass")
	mid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO chat_messages (id, user_id, username, message) VALUES (?, ?, ?, ?)",
		mid, uid, "chatuser4", "delete me",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Delete("/api/chat/messages/{id}", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/chat/messages/"+mid, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM chat_messages WHERE id = ?", mid).Scan(&count)
	if count != 0 {
		t.Error("expected message to be deleted")
	}
}

func TestChat_DeleteNotFound(t *testing.T) {
	d := openTestDB(t)
	hub := ws.NewHub()
	go hub.Run()
	handler := api.NewChatHandler(d, hub)

	r := chi.NewRouter()
	r.Delete("/api/chat/messages/{id}", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/chat/messages/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestChat_ListBadSince(t *testing.T) {
	d := openTestDB(t)
	hub := ws.NewHub()
	go hub.Run()
	handler := api.NewChatHandler(d, hub)

	r := chi.NewRouter()
	r.Get("/api/chat/messages", handler.List)

	req := httptest.NewRequest(http.MethodGet, "/api/chat/messages?since=not-a-date", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
