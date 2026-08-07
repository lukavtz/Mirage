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
	"zialfi-panel/internal/testutil"
)

func TestNotes_Create(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)
	uid := createTestUser(t, d, "notes-create", "pass")
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, owner_id, build_id, hwid, os, username, ip, country_code, created_at) VALUES ($1, $2, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid, uid); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/notes", handler.Create)
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/notes", strings.NewReader(`{"content":"investigate this session"}`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["id"] == "" || resp["content"] != "investigate this session" || resp["session_id"] != sid {
		t.Errorf("unexpected response: %v", resp)
	}
	if resp["created_by"] != "admin" || resp["created_at"] == "" {
		t.Errorf("unexpected metadata: %v", resp)
	}
}

func TestNotes_List(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)
	uid, sid := "", uuid.New().String()
	uid = createTestUser(t, d, "notes-list", "pass")
	if _, err := d.Exec(`INSERT INTO sessions (id, owner_id, build_id, hwid, os, username, ip, country_code, created_at) VALUES ($1, $2, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid, uid); err != nil {
		t.Fatal(err)
	}
	nid := uuid.New().String()
	if _, err := d.Exec("INSERT INTO notes (id, session_id, content) VALUES ($1, $2, $3)", nid, sid, "test note"); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/notes", handler.List)
	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"/notes", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var notes []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &notes); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 || notes[0]["id"] != nid || notes[0]["content"] != "test note" || notes[0]["session_id"] != sid {
		t.Errorf("unexpected notes: %v", notes)
	}
}

func TestNotes_Delete(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)
	uid := createTestUser(t, d, "notes-delete", "pass")
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, owner_id, build_id, hwid, os, username, ip, country_code, created_at) VALUES ($1, $2, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid, uid); err != nil {
		t.Fatal(err)
	}
	nid := uuid.New().String()
	if _, err := d.Exec("INSERT INTO notes (id, session_id, content) VALUES ($1, $2, $3)", nid, sid, "delete me"); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Delete("/api/notes/{id}", handler.Delete)
	req := httptest.NewRequest(http.MethodDelete, "/api/notes/"+nid, nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var count int
	d.QueryRow("SELECT COUNT(*) FROM notes WHERE id = $1", nid).Scan(&count)
	if count != 0 {
		t.Error("expected note to be deleted")
	}
}

func TestNotes_DeleteNotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)
	r := chi.NewRouter()
	r.Delete("/api/notes/{id}", handler.Delete)
	req := httptest.NewRequest(http.MethodDelete, "/api/notes/"+uuid.New().String(), nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestNotes_EmptyList(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)
	uid := createTestUser(t, d, "notes-empty", "pass")
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, owner_id, build_id, hwid, os, username, ip, country_code, created_at) VALUES ($1, $2, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', CURRENT_TIMESTAMP)`, sid, uid); err != nil {
		t.Fatal(err)
	}
	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/notes", handler.List)
	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"/notes", nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var notes []any
	json.Unmarshal(w.Body.Bytes(), &notes)
	if len(notes) != 0 {
		t.Errorf("expected empty list, got %d", len(notes))
	}
}
