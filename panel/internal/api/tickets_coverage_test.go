package api_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/testutil"
)

func insertTicket(t *testing.T, d *sql.DB, id, userID string) {
	t.Helper()
	now := "2026-01-01T00:00:00Z"
	if _, err := d.Exec("INSERT INTO support_tickets (id, user_id, subject, category, status, created_at, updated_at) VALUES ($1, $2, $3, $4, 'open', $5, $6)",
		id, userID, "Test subject", "bug", now, now); err != nil {
		t.Fatal(err)
	}
}

// authedReq builds a request with claims injected and routes it through r.
func authedReq(r *chi.Mux, method, path string, body any, uid, role string) *httptest.ResponseRecorder {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if uid != "" {
		req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: role}))
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func ticketRouter(h *api.TicketHandler) *chi.Mux {
	r := chi.NewRouter()
	r.Post("/tickets", h.Create)
	r.Get("/tickets", h.List)
	r.Get("/tickets/{id}", h.Get)
	r.Post("/tickets/{id}/reply", h.Reply)
	r.Post("/tickets/{id}/close", h.Close)
	return r
}

func TestTickets_Create(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTicketHandler(d)
	r := ticketRouter(h)

	w := authedReq(r, "POST", "/tickets", map[string]string{"subject": "Help", "category": "bug"}, "u1", "user")
	if w.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil || created.ID == "" {
		t.Fatalf("create: bad body %s", w.Body.String())
	}

	w = authedReq(r, "POST", "/tickets", map[string]string{"category": "bug"}, "u1", "user")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing subject: expected 400, got %d", w.Code)
	}
	w = authedReq(r, "POST", "/tickets", map[string]string{"subject": "x", "category": "nope"}, "u1", "user")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("invalid category: expected 400, got %d", w.Code)
	}
	w = authedReq(r, "POST", "/tickets", "not-json", "u1", "user")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad json: expected 400, got %d", w.Code)
	}
	w = authedReq(r, "POST", "/tickets", map[string]string{"subject": "x", "category": "bug"}, "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: expected 401, got %d", w.Code)
	}
}

func TestTickets_List(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTicketHandler(d)
	r := ticketRouter(h)
	insertTicket(t, d, "t1", "u1")
	insertTicket(t, d, "t2", "other-user")

	w := authedReq(r, "GET", "/tickets", nil, "u1", "user")
	if w.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", w.Code)
	}
	var list []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("list body: %s", w.Body.String())
	}
	if len(list) != 1 {
		t.Fatalf("list: expected 1 own ticket, got %d", len(list))
	}

	w = authedReq(r, "GET", "/tickets", nil, "admin-uid", "admin")
	if w.Code != http.StatusOK {
		t.Fatalf("admin list: expected 200, got %d", w.Code)
	}
	json.Unmarshal(w.Body.Bytes(), &list)
	if len(list) != 2 {
		t.Fatalf("admin list: expected 2, got %d", len(list))
	}

	w = authedReq(r, "GET", "/tickets", nil, "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth list: expected 401, got %d", w.Code)
	}
}

func TestTickets_Get(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTicketHandler(d)
	r := ticketRouter(h)
	insertTicket(t, d, "t1", "u1")

	w := authedReq(r, "GET", "/tickets/t1", nil, "u1", "user")
	if w.Code != http.StatusOK {
		t.Fatalf("get own: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var detail map[string]any
	json.Unmarshal(w.Body.Bytes(), &detail)
	if detail["subject"] != "Test subject" {
		t.Fatalf("get body: %s", w.Body.String())
	}

	w = authedReq(r, "GET", "/tickets/t1", nil, "stranger", "user")
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign get: expected 403, got %d", w.Code)
	}
	w = authedReq(r, "GET", "/tickets/nope", nil, "u1", "user")
	if w.Code != http.StatusNotFound {
		t.Fatalf("missing get: expected 404, got %d", w.Code)
	}
}

func TestTickets_Reply(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTicketHandler(d)
	r := ticketRouter(h)
	insertTicket(t, d, "t1", "owner")

	w := authedReq(r, "POST", "/tickets/t1/reply", map[string]string{"message": "hello"}, "owner", "user")
	if w.Code != http.StatusCreated {
		t.Fatalf("owner reply: expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var rpl map[string]any
	json.Unmarshal(w.Body.Bytes(), &rpl)
	if rpl["message"] != "hello" {
		t.Fatalf("reply body: %s", w.Body.String())
	}

	w = authedReq(r, "POST", "/tickets/t1/reply", map[string]string{"message": "hi"}, "other", "user")
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign reply: expected 403, got %d", w.Code)
	}
	w = authedReq(r, "POST", "/tickets/t1/reply", map[string]string{"message": "admin here"}, "admin-id", "admin")
	if w.Code != http.StatusCreated {
		t.Fatalf("admin reply: expected 201, got %d", w.Code)
	}
	w = authedReq(r, "POST", "/tickets/t1/reply", map[string]string{"message": ""}, "owner", "user")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("empty message: expected 400, got %d", w.Code)
	}
	w = authedReq(r, "POST", "/tickets/nope/reply", map[string]string{"message": "x"}, "owner", "user")
	if w.Code != http.StatusNotFound {
		t.Fatalf("nonexistent reply: expected 404, got %d", w.Code)
	}
}

func TestTickets_Close(t *testing.T) {
	d := testutil.OpenTestDB(t)
	h := api.NewTicketHandler(d)
	r := ticketRouter(h)
	insertTicket(t, d, "t1", "owner")
	insertTicket(t, d, "t2", "someone-else")

	w := authedReq(r, "POST", "/tickets/t1/close", nil, "owner", "user")
	if w.Code != http.StatusOK {
		t.Fatalf("close: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	w = authedReq(r, "POST", "/tickets/t1/close", nil, "owner", "user")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("re-close: expected 400, got %d", w.Code)
	}
	w = authedReq(r, "POST", "/tickets/nope/close", nil, "owner", "user")
	if w.Code != http.StatusNotFound {
		t.Fatalf("nonexistent close: expected 404, got %d", w.Code)
	}
	w = authedReq(r, "POST", "/tickets/t2/close", nil, "owner", "user")
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign close: expected 403, got %d", w.Code)
	}
	w = authedReq(r, "POST", "/tickets/t1/close", nil, "", "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth close: expected 401, got %d", w.Code)
	}
}
