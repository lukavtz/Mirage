package api_test

import (
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
)

func TestTicket_Create(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewTicketHandler(d)

	uid := createTestUser(t, d, "ticketuser", "pass")

	r := chi.NewRouter()
	r.Post("/api/support/tickets", handler.Create)

	body := `{"subject":"help needed","category":"bug"}`
	req := httptest.NewRequest(http.MethodPost, "/api/support/tickets", strings.NewReader(body))
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
		t.Error("expected ticket id")
	}
	if resp["subject"] != "help needed" {
		t.Errorf("subject = %v, want %q", resp["subject"], "help needed")
	}
	if resp["category"] != "bug" {
		t.Errorf("category = %v, want %q", resp["category"], "bug")
	}
	if resp["status"] != "open" {
		t.Errorf("status = %v, want %q", resp["status"], "open")
	}
}

func TestTicket_CreateInvalidCategory(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewTicketHandler(d)

	uid := createTestUser(t, d, "ticketuser2", "pass")

	r := chi.NewRouter()
	r.Post("/api/support/tickets", handler.Create)

	body := `{"subject":"bad","category":"invalid"}`
	req := httptest.NewRequest(http.MethodPost, "/api/support/tickets", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTicket_ListUserSeesOwn(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewTicketHandler(d)

	uid := createTestUser(t, d, "ticketuser3", "pass")
	_, err := d.Exec(
		"INSERT INTO support_tickets (id, user_id, subject, category) VALUES (?, ?, ?, ?)",
		uuid.New().String(), uid, "my issue", "bug",
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(
		"INSERT INTO support_tickets (id, user_id, subject, category) VALUES (?, ?, ?, ?)",
		uuid.New().String(), "other-user", "not mine", "question",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/support/tickets", handler.List)

	req := httptest.NewRequest(http.MethodGet, "/api/support/tickets", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var tickets []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &tickets); err != nil {
		t.Fatal(err)
	}
	if len(tickets) != 1 {
		t.Fatalf("expected 1 ticket, got %d", len(tickets))
	}
	if tickets[0]["subject"] != "my issue" {
		t.Errorf("subject = %v, want %q", tickets[0]["subject"], "my issue")
	}
}

func TestTicket_ListAdminSeesAll(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewTicketHandler(d)

	uid := createTestUser(t, d, "adminuser", "pass")
	_, err := d.Exec(
		"INSERT INTO support_tickets (id, user_id, subject, category) VALUES (?, ?, ?, ?)",
		uuid.New().String(), uid, "admin ticket", "feature",
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec(
		"INSERT INTO support_tickets (id, user_id, subject, category) VALUES (?, ?, ?, ?)",
		uuid.New().String(), "other-user", "other ticket", "bug",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/support/tickets", handler.List)

	req := httptest.NewRequest(http.MethodGet, "/api/support/tickets", nil)
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var tickets []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &tickets); err != nil {
		t.Fatal(err)
	}
	if len(tickets) != 2 {
		t.Fatalf("expected 2 tickets, got %d", len(tickets))
	}
}

func TestTicket_Get(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewTicketHandler(d)

	uid := createTestUser(t, d, "ticketuser4", "pass")
	tid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO support_tickets (id, user_id, subject, category) VALUES (?, ?, ?, ?)",
		tid, uid, "my ticket", "question",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/support/tickets/{id}", handler.Get)

	req := httptest.NewRequest(http.MethodGet, "/api/support/tickets/"+tid, nil)
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
	if resp["subject"] != "my ticket" {
		t.Errorf("subject = %v, want %q", resp["subject"], "my ticket")
	}
	replies := resp["replies"].([]any)
	if len(replies) != 0 {
		t.Errorf("expected empty replies, got %d", len(replies))
	}
}

func TestTicket_GetForbidden(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewTicketHandler(d)

	uid := createTestUser(t, d, "ticketuser5", "pass")
	tid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO support_tickets (id, user_id, subject, category) VALUES (?, ?, ?, ?)",
		tid, "other-owner", "not mine", "bug",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/support/tickets/{id}", handler.Get)

	req := httptest.NewRequest(http.MethodGet, "/api/support/tickets/"+tid, nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTicket_Reply(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewTicketHandler(d)

	uid := createTestUser(t, d, "ticketuser6", "pass")
	tid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO support_tickets (id, user_id, subject, category) VALUES (?, ?, ?, ?)",
		tid, uid, "reply test", "bug",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/support/tickets/{id}/reply", handler.Reply)

	body := `{"message":"thank you for the help"}`
	req := httptest.NewRequest(http.MethodPost, "/api/support/tickets/"+tid+"/reply", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: uid, Role: "user"}
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
	if resp["message"] != "thank you for the help" {
		t.Errorf("message = %v, want %q", resp["message"], "thank you for the help")
	}
}

func TestTicket_Close(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewTicketHandler(d)

	uid := createTestUser(t, d, "ticketuser7", "pass")
	tid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO support_tickets (id, user_id, subject, category) VALUES (?, ?, ?, ?)",
		tid, uid, "close test", "other",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/support/tickets/{id}/close", handler.Close)

	req := httptest.NewRequest(http.MethodPost, "/api/support/tickets/"+tid+"/close", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var status string
	d.QueryRow("SELECT status FROM support_tickets WHERE id = ?", tid).Scan(&status)
	if status != "closed" {
		t.Errorf("status = %q, want %q", status, "closed")
	}
}

func TestTicket_CloseAlreadyClosed(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewTicketHandler(d)

	uid := createTestUser(t, d, "ticketuser8", "pass")
	tid := uuid.New().String()
	_, err := d.Exec(
		"INSERT INTO support_tickets (id, user_id, subject, category, status) VALUES (?, ?, ?, ?, 'closed')",
		tid, uid, "already closed", "bug",
	)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/support/tickets/{id}/close", handler.Close)

	req := httptest.NewRequest(http.MethodPost, "/api/support/tickets/"+tid+"/close", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
