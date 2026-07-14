package api

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
)

type DocsHandler struct{}

func NewDocsHandler() *DocsHandler {
	return &DocsHandler{}
}

type DocFile struct {
	Path  string `json:"path"`
	Title string `json:"title"`
}

type DocListResponse struct {
	Docs []DocFile `json:"docs"`
}

type DocContentResponse struct {
	Content string `json:"content"`
	Title   string `json:"title"`
}

func docsDir() string {
	cwd, _ := os.Getwd()
	return filepath.Join(cwd, "docs")
}

func docTitle(name string) string {
	s := strings.TrimSuffix(name, ".md")
	s = strings.ReplaceAll(s, "-", " ")
	s = strings.ReplaceAll(s, "_", " ")
	if len(s) == 0 {
		return s
	}
	// Simple title case
	upper := true
	runes := []rune(s)
	for i, r := range runes {
		if upper {
			if r >= 'a' && r <= 'z' {
				runes[i] = r - 32
			}
			upper = false
		}
		if r == ' ' {
			upper = true
		}
	}
	return string(runes)
}

func (h *DocsHandler) List(w http.ResponseWriter, r *http.Request) {
	dir := docsDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		writeJSON(w, http.StatusOK, DocListResponse{Docs: []DocFile{}})
		return
	}

	docs := make([]DocFile, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		docs = append(docs, DocFile{
			Path:  strings.TrimSuffix(entry.Name(), ".md"),
			Title: docTitle(entry.Name()),
		})
	}

	writeJSON(w, http.StatusOK, DocListResponse{Docs: docs})
}

func (h *DocsHandler) Get(w http.ResponseWriter, r *http.Request) {
	path := chi.URLParam(r, "*")
	if path == "" {
		writeError(w, http.StatusBadRequest, "missing doc path")
		return
	}

	clean := filepath.Clean(path)
	if strings.Contains(clean, "..") {
		writeError(w, http.StatusBadRequest, "invalid path")
		return
	}

	filePath := filepath.Join(docsDir(), clean+".md")
	content, err := os.ReadFile(filePath)
	if err != nil {
		writeError(w, http.StatusNotFound, "doc not found")
		return
	}

	title := docTitle(clean)
	writeJSON(w, http.StatusOK, DocContentResponse{
		Content: string(content),
		Title:   title,
	})
}
