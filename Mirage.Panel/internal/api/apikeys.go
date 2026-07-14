package api

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type APIKeyHandler struct {
	db *sql.DB
}

type APIKeyResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Key       string `json:"key,omitempty"`
	Scope     string `json:"scope"`
	RateLimit int    `json:"rate_limit"`
	CreatedAt string `json:"created_at"`
}

func NewAPIKeyHandler(db *sql.DB) *APIKeyHandler {
	return &APIKeyHandler{db: db}
}

func generateAPIKey() (string, string) {
	b := make([]byte, 32)
	rand.Read(b)
	raw := hex.EncodeToString(b)
	hash := sha256.Sum256([]byte(raw))
	return raw, fmt.Sprintf("%x", hash)
}

func (h *APIKeyHandler) Create(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Name      string `json:"name"`
		Scope     string `json:"scope"`
		RateLimit int    `json:"rate_limit"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.Scope == "" {
		req.Scope = "read"
	}
	if req.RateLimit <= 0 {
		req.RateLimit = 100
	}

	id := uuid.New().String()
	rawKey, keyHash := generateAPIKey()

	_, err := h.db.Exec(
		"INSERT INTO api_keys (id, user_id, name, key_hash, scope, rate_limit) VALUES (?, ?, ?, ?, ?, ?)",
		id, claims.UserID, req.Name, keyHash, req.Scope, req.RateLimit,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create API key")
		return
	}

	writeJSON(w, http.StatusCreated, APIKeyResponse{
		ID:        id,
		Name:      req.Name,
		Key:       rawKey,
		Scope:     req.Scope,
		RateLimit: req.RateLimit,
	})
}

func (h *APIKeyHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	rows, err := h.db.Query(
		"SELECT id, name, scope, rate_limit, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
		claims.UserID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list API keys")
		return
	}
	defer rows.Close()

	items := make([]APIKeyResponse, 0)
	for rows.Next() {
		var item APIKeyResponse
		if err := rows.Scan(&item.ID, &item.Name, &item.Scope, &item.RateLimit, &item.CreatedAt); err != nil {
			continue
		}
		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{"keys": items})
}

func (h *APIKeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := chi.URLParam(r, "id")

	result, err := h.db.Exec("DELETE FROM api_keys WHERE id = ? AND user_id = ?", id, claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete API key")
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeError(w, http.StatusNotFound, "API key not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "API key revoked"})
}
