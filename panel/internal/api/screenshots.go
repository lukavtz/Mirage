package api

import (
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

type ScreenshotsHandler struct {
	db *sql.DB
}

func NewScreenshotsHandler(db *sql.DB) *ScreenshotsHandler {
	return &ScreenshotsHandler{db: db}
}

// Get serves a session's captured screenshot. Tenant-scoped: non-admins only
// see their own sessions, otherwise the response is 404 (not 403) to avoid
// leaking session existence across tenants.
func (h *ScreenshotsHandler) Get(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	if !sessionOwnedBy(h.db, r, sessionID) {
		http.NotFound(w, r)
		return
	}

	var relPath, mime string
	err := h.db.QueryRow(
		"SELECT file_path, mime_type FROM screenshots WHERE session_id = ?", sessionID,
	).Scan(&relPath, &mime)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	absRoot, err := filepath.Abs(filepath.Join("data", "screenshots"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "path resolution failed")
		return
	}
	abs, err := filepath.Abs(relPath)
	if err != nil || !strings.HasPrefix(abs, absRoot+string(os.PathSeparator)) {
		http.NotFound(w, r)
		return
	}

	info, err := os.Stat(abs)
	if err != nil || info.IsDir() {
		http.Error(w, "screenshot missing on disk", http.StatusGone)
		return
	}

	if mime == "" {
		mime = "image/bmp"
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.Header().Set("Content-Disposition", "inline; filename=\""+sessionID+".bmp\"")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	http.ServeContent(w, r, sessionID+".bmp", info.ModTime(), mustOpen(abs))
}

func mustOpen(p string) *os.File {
	f, err := os.Open(p)
	if err != nil {
		return nil
	}
	return f
}

// Delete removes a session's screenshot file and row. Admin-only — the route
// is mounted behind middleware.RequireRole("admin").
func (h *ScreenshotsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "missing session id")
		return
	}

	var relPath string
	err := h.db.QueryRow(
		"SELECT file_path FROM screenshots WHERE session_id = ?", sessionID,
	).Scan(&relPath)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	if _, err := h.db.Exec("DELETE FROM screenshots WHERE session_id = ?", sessionID); err != nil {
		writeError(w, http.StatusInternalServerError, "delete failed")
		return
	}
	// Best-effort file removal; missing file is not an error.
	_ = os.Remove(relPath)

	w.WriteHeader(http.StatusNoContent)
}
