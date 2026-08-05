package api_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

func TestExport_Netscape_Unauthorized(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewExportHandler(d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/export", handler.ExportSession)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/abc/export?format=netscape", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExport_Netscape_NotFound(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewExportHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "expnf", "pass")

	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/export", handler.ExportSession)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/nonexistent/export?format=netscape", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExport_Netscape_Forbidden(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewExportHandler(d, db.ProviderSQLite)

	owner := createTestUser(t, d, "expowner", "pass")
	other := createTestUserWithRole(t, d, "expother", "pass", "user")

	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', ?, datetime('now'))`, sid, owner); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/export", handler.ExportSession)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"/export?format=netscape", nil)
	claims := &auth.Claims{UserID: other, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestExport_Netscape_EmptyCookies(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewExportHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "expempty", "pass")

	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', ?, datetime('now'))`, sid, uid); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/export", handler.ExportSession)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"/export?format=netscape", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Netscape HTTP Cookie File") {
		t.Errorf("expected header comment in body, got %q", w.Body.String())
	}
}

func TestExport_Netscape_CookiesWithMissingPath(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewExportHandler(d, db.ProviderSQLite)

	uid := createTestUser(t, d, "expcookies", "pass")

	sid := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, owner_id, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'u', '1.2.3.4', 'US', ?, datetime('now'))`, sid, uid); err != nil {
		t.Fatal(err)
	}

	// Cookie with domain but empty path -> export defaults path to "/"
	if _, err := d.Exec(
		`INSERT INTO cookies (id, session_id, name, domain, value, path) VALUES (?, ?, 'sid', 'example.com', 'abc', '')`,
		uuid.New().String(), sid,
	); err != nil {
		t.Fatal(err)
	}
	// Cookie with empty domain -> skipped by export
	if _, err := d.Exec(
		`INSERT INTO cookies (id, session_id, name, domain, value, path) VALUES (?, ?, 'nodom', '', 'x', '/')`,
		uuid.New().String(), sid,
	); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/sessions/{id}/export", handler.ExportSession)

	req := httptest.NewRequest(http.MethodGet, "/api/sessions/"+sid+"/export?format=netscape", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	body := w.Body.String()
	if !strings.Contains(body, ".example.com") {
		t.Errorf("expected domain .example.com in export, got %q", body)
	}
	if strings.Contains(body, "nodom") {
		t.Errorf("cookie with empty domain should be skipped, got %q", body)
	}
}
