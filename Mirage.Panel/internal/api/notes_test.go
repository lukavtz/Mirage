package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/user/mirage-panel/internal/api"
)

func TestNotes_Create(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewNotesHandler(d)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/notes", handler.Create)

	body := `{"content":"investigate this session"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/notes", strings.NewReader(body))
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
	if resp["id"] == "" {
		t.Error("expected note id")
	}
	if resp["content"] != "investigate this session" {
		t.Errorf("content = %v, want %q", resp["content"], "investigate this session")
	}
	if resp["session_id"] != sid {
		t.Errorf("session_id = %v, want %s", resp["session_id"], sid)
	}
	if resp["created_by"] != "admin" {
		t.Errorf("created_by = %v, want admin", resp["created_by"])
	}
	if resp["created_at"] == "" {
		t.Error("expected created_at")
	}
}

func TestNotes_List(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewNotesHandler(d)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	nid := uuid.New().String()
	_, err = d.Exec("INSERT INTO notes (id, session_id, content) VALUES (?, ?, ?)", nid, sid, "test note")
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/notes", handler.List)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"/notes", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var notes []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &notes); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 1 {
		t.Fatalf("expected 1 note, got %d", len(notes))
	}
	if notes[0]["id"] != nid {
		t.Errorf("expected note id %s, got %v", nid, notes[0]["id"])
	}
	if notes[0]["content"] != "test note" {
		t.Errorf("content = %v, want %q", notes[0]["content"], "test note")
	}
	if notes[0]["session_id"] != sid {
		t.Errorf("session_id = %v, want %s", notes[0]["session_id"], sid)
	}
}

func TestNotes_Delete(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewNotesHandler(d)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	nid := uuid.New().String()
	_, err = d.Exec("INSERT INTO notes (id, session_id, content) VALUES (?, ?, ?)", nid, sid, "delete me")
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Delete("/api/notes/{id}", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/notes/"+nid, nil)
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

	var count int
	d.QueryRow("SELECT COUNT(*) FROM notes WHERE id = ?", nid).Scan(&count)
	if count != 0 {
		t.Error("expected note to be deleted")
	}
}

func TestNotes_DeleteNotFound(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewNotesHandler(d)

	r := chi.NewRouter()
	r.Delete("/api/notes/{id}", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/notes/"+uuid.New().String(), nil)
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

func TestNotes_EmptyList(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewNotesHandler(d)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user', '1.2.3.4', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/notes", handler.List)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"/notes", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var notes []any
	if err := json.Unmarshal(w.Body.Bytes(), &notes); err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Errorf("expected empty list, got %d items", len(notes))
	}
}
