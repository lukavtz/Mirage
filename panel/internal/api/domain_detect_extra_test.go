package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/db"
)

func TestDomainDetect_Create_Success(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewDomainDetectHandler(d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Post("/api/detect/rules", handler.Create)

	body := `{"domain":"example.com","tag":"phishing"}`
	req := httptest.NewRequest(http.MethodPost, "/api/detect/rules", strings.NewReader(body))
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
	if resp["domain"] != "example.com" {
		t.Errorf("domain = %v", resp["domain"])
	}
	if resp["color"] != "#5865F2" {
		t.Errorf("color = %v, want default #5865F2", resp["color"])
	}
}

func TestDomainDetect_Create_MissingFields(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewDomainDetectHandler(d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Post("/api/detect/rules", handler.Create)

	cases := []string{`{"domain":"","tag":"x"}`, `{"domain":"d","tag":""}`, `{}`}
	for _, body := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/detect/rules", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %s: expected 400, got %d: %s", body, w.Code, w.Body.String())
		}
	}
}

func TestDomainDetect_Create_InvalidJSON(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewDomainDetectHandler(d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Post("/api/detect/rules", handler.Create)

	req := httptest.NewRequest(http.MethodPost, "/api/detect/rules", bytes.NewReader([]byte(`bad`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDomainDetect_Delete_Success(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewDomainDetectHandler(d, db.ProviderSQLite)

	id := uuid.New().String()
	if _, err := d.Exec("INSERT INTO domain_detect (id, domain, tag, color) VALUES (?, 'd.com', 'tag', '#fff')", id); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Delete("/api/detect/rules/{id}", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/detect/rules/"+id, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDomainDetect_Delete_NotFound(t *testing.T) {
	d := openTestDB(t)
	handler := api.NewDomainDetectHandler(d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Delete("/api/detect/rules/{id}", handler.Delete)

	req := httptest.NewRequest(http.MethodDelete, "/api/detect/rules/nonexistent", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}
