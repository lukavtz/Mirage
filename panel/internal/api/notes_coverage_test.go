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

// Create coverage: empty content → 400
func TestNotesCoverage_Create_EmptyContent(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)

	sid := uuid.New().String()
	uid := createTestUser(t, d, "notes-empty-content", "pass")
	_, err := d.Exec("INSERT INTO sessions (id, owner_id, build_id) VALUES ($1, $2, $3)",
		sid, uid, uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/notes", handler.Create)

	body := `{"content":""}`
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/notes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

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

// Create coverage: invalid JSON → 400
func TestNotesCoverage_Create_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)

	sid := uuid.New().String()
	uid := createTestUser(t, d, "notes-invalid-json", "pass")
	_, err := d.Exec("INSERT INTO sessions (id, owner_id, build_id) VALUES ($1, $2, $3)",
		sid, uid, uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/notes", handler.Create)

	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/notes",
		strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

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

// Create coverage: nonexistent session with admin claims → 500 (FK violation)
func TestNotesCoverage_Create_NonexistentSessionAdmin(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)

	uid := createTestUser(t, d, "notes-nonexistent-admin", "pass")

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/notes", handler.Create)

	body := `{"content":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+uuid.New().String()+"/notes",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "admin"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}

// Create coverage: nonexistent session with user claims → 403 (sessionOwnedBy false)
func TestNotesCoverage_Create_NonexistentSessionUser(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)

	uid := createTestUser(t, d, "notes-nonexistent-user", "pass")

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/notes", handler.Create)

	body := `{"content":"test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+uuid.New().String()+"/notes",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// Create coverage: user creates note on own session → 201
func TestNotesCoverage_Create_OwnSessionUser(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)

	sid := uuid.New().String()
	uid := createTestUser(t, d, "notes-own-session", "pass")
	_, err := d.Exec("INSERT INTO sessions (id, owner_id, build_id) VALUES ($1, $2, $3)",
		sid, uid, uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/notes", handler.Create)

	body := `{"content":"user's own note"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/notes", strings.NewReader(body))
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
	if resp["id"] == "" {
		t.Error("expected note id")
	}
	if resp["content"] != "user's own note" {
		t.Errorf("content = %v, want %q", resp["content"], "user's own note")
	}
	if resp["session_id"] != sid {
		t.Errorf("session_id = %v, want %s", resp["session_id"], sid)
	}
}

// Create coverage: user creates note on another user's session → 403
func TestNotesCoverage_Create_OtherSessionUser(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)

	sid := uuid.New().String()
	otherUID := createTestUser(t, d, "notes-other-owner", "pass")
	uid := createTestUser(t, d, "notes-other-user", "pass")
	_, err := d.Exec("INSERT INTO sessions (id, owner_id, build_id) VALUES ($1, $2, $3)",
		sid, otherUID, uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/sessions/{id}/notes", handler.Create)

	body := `{"content":"someone else's session"}`
	req := httptest.NewRequest(http.MethodPost, "/api/sessions/"+sid+"/notes", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// Delete coverage: admin deletes valid note → 200
func TestNotesCoverage_Delete_Admin(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)

	sid := uuid.New().String()
	uid := createTestUser(t, d, "notes-del-admin", "pass")
	_, err := d.Exec("INSERT INTO sessions (id, owner_id, build_id) VALUES ($1, $2, $3)",
		sid, uid, uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	nid := uuid.New().String()
	_, err = d.Exec("INSERT INTO notes (id, session_id, content) VALUES ($1, $2, $3)", nid, sid, "delete me")
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Delete("/api/notes/{id}", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/notes/"+nid, nil)
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
	var count int
	d.QueryRow("SELECT COUNT(*) FROM notes WHERE id = $1", nid).Scan(&count)
	if count != 0 {
		t.Error("expected note to be deleted")
	}
}

// Delete coverage: delete valid note without claims → 403 (fail closed)
func TestNotesCoverage_Delete_NoClaims(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)

	sid := uuid.New().String()
	_, err := d.Exec("INSERT INTO sessions (id, owner_id, build_id) VALUES ($1, $2, $3)",
		sid, uuid.New().String(), uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	nid := uuid.New().String()
	_, err = d.Exec("INSERT INTO notes (id, session_id, content) VALUES ($1, $2, $3)", nid, sid, "no claims")
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Delete("/api/notes/{id}", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/notes/"+nid, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

// Delete coverage: delete nonexistent note → 404
func TestNotesCoverage_Delete_NotFound(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)

	uid := createTestUser(t, d, "notes-del-notfound", "pass")

	r := chi.NewRouter()
	r.Delete("/api/notes/{id}", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/notes/"+uuid.New().String(), nil)
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

// Delete coverage: user deletes note on another user's session → 403
func TestNotesCoverage_Delete_Forbidden(t *testing.T) {
	d := testutil.OpenTestDB(t)
	handler := api.NewNotesHandler(d)

	sid := uuid.New().String()
	otherUID := createTestUser(t, d, "notes-del-other-owner", "pass")
	uid := createTestUser(t, d, "notes-del-forbidden", "pass")
	_, err := d.Exec("INSERT INTO sessions (id, owner_id, build_id) VALUES ($1, $2, $3)",
		sid, otherUID, uuid.New().String())
	if err != nil {
		t.Fatal(err)
	}
	nid := uuid.New().String()
	_, err = d.Exec("INSERT INTO notes (id, session_id, content) VALUES ($1, $2, $3)", nid, sid, "not yours")
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Delete("/api/notes/{id}", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/notes/"+nid, nil)
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), &auth.Claims{UserID: uid, Role: "user"}))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}
