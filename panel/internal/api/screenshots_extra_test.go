package api_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

func TestScreenshot_Get_MissingID(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewScreenshotsHandler(d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/screenshot", handler.Get)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions//screenshot", nil)
	claims := &auth.Claims{UserID: uuid.New().String(), Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestScreenshot_Get_NoScreenshot(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewScreenshotsHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "shotmiss", "pass")
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', ?, datetime('now'))`, sid, uid); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/screenshot", handler.Get)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"/screenshot", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestScreenshot_Get_FileMissing(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewScreenshotsHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "shotgone", "pass")
	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', ?, datetime('now'))`, sid, uid); err != nil {
		t.Fatal(err)
	}
	// Row exists but file path points at a missing file
	rel := filepath.Join("data", "screenshots", "missing.bmp")
	if _, err := d.Exec(
		"INSERT INTO screenshots (id, session_id, file_path, mime_type, size_bytes) VALUES (?, ?, ?, 'image/bmp', 0)",
		uuid.New().String(), sid, rel,
	); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/screenshot", handler.Get)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"/screenshot", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusGone {
		t.Fatalf("expected 410, got %d: %s", w.Code, w.Body.String())
	}
}

func TestScreenshot_Delete_MissingID(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewScreenshotsHandler(d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Delete("/api/sessions/{id}/screenshot", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/sessions//screenshot", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestScreenshot_Delete_NotFound(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewScreenshotsHandler(d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Delete("/api/sessions/{id}/screenshot", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/sessions/nonexistent/screenshot", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestScreenshot_Delete_Success(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewScreenshotsHandler(d, db.ProviderSQLite)

	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', datetime('now'))`, sid); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	img := filepath.Join(dir, "shot.bmp")
	if err := os.WriteFile(img, []byte("bmp"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(
		"INSERT INTO screenshots (id, session_id, file_path, mime_type, size_bytes) VALUES (?, ?, ?, 'image/bmp', 3)",
		uuid.New().String(), sid, img,
	); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Delete("/api/sessions/{id}/screenshot", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/sessions/"+sid+"/screenshot", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.Stat(img); !os.IsNotExist(err) {
		t.Errorf("expected screenshot file to be removed, stat err=%v", err)
	}
}
