package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/api"
)

func TestDocs_List_EmptyDir(t *testing.T) {
	// Point DOCS_DIR at an empty temp dir so List exercises the no-docs path
	t.Setenv("DOCS_DIR", t.TempDir())
	h := api.NewDocsHandler()
	r := chi.NewRouter()
	r.Get("/api/docs", h.List)

	req := httptest.NewRequest(http.MethodGet, "/api/docs", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp api.DocListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Docs) != 0 {
		t.Errorf("expected 0 docs, got %d", len(resp.Docs))
	}
}

func TestDocs_List_WithDocs(t *testing.T) {
	dir := t.TempDir()
	content := "# Getting Started\n\nDocs content here.\n"
	if err := os.WriteFile(filepath.Join(dir, "getting-started.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "not-a-doc.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCS_DIR", dir)
	h := api.NewDocsHandler()
	r := chi.NewRouter()
	r.Get("/api/docs", h.List)

	req := httptest.NewRequest(http.MethodGet, "/api/docs", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp api.DocListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Docs) != 1 {
		t.Fatalf("expected 1 doc, got %d", len(resp.Docs))
	}
	if resp.Docs[0].Path != "getting-started" {
		t.Errorf("path = %q, want %q", resp.Docs[0].Path, "getting-started")
	}
	if resp.Docs[0].Title != "Getting Started" {
		t.Errorf("title = %q, want %q", resp.Docs[0].Title, "Getting Started")
	}
}

func TestDocs_Get_Success(t *testing.T) {
	dir := t.TempDir()
	content := "# My Doc\n\nBody.\n"
	if err := os.WriteFile(filepath.Join(dir, "my-doc.md"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCS_DIR", dir)
	h := api.NewDocsHandler()
	r := chi.NewRouter()
	r.Get("/api/docs/*", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/api/docs/my-doc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp api.DocContentResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Content != content {
		t.Errorf("content = %q, want %q", resp.Content, content)
	}
	if resp.Title != "My Doc" {
		t.Errorf("title = %q, want %q", resp.Title, "My Doc")
	}
}

func TestDocs_Get_MissingPath(t *testing.T) {
	t.Setenv("DOCS_DIR", t.TempDir())
	h := api.NewDocsHandler()

	req := httptest.NewRequest(http.MethodGet, "/api/docs", nil)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDocs_Get_Traversal(t *testing.T) {
	t.Setenv("DOCS_DIR", t.TempDir())
	h := api.NewDocsHandler()
	r := chi.NewRouter()
	r.Get("/api/docs/*", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/api/docs/../secret", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDocs_Get_NotFound(t *testing.T) {
	t.Setenv("DOCS_DIR", t.TempDir())
	h := api.NewDocsHandler()
	r := chi.NewRouter()
	r.Get("/api/docs/*", h.Get)

	req := httptest.NewRequest(http.MethodGet, "/api/docs/missing-doc", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}
