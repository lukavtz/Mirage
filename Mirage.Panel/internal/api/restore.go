package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/user/mirage-panel/internal/db"
)

type RestoreHandler struct {
	db *sql.DB
}

func NewRestoreHandler(db *sql.DB) *RestoreHandler {
	return &RestoreHandler{db: db}
}

type restoreRequest struct {
	SessionID string `json:"session_id"`
	Proxy     string `json:"proxy"`
}

type restoreCookie struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	Path   string `json:"path"`
}

type restoreResponse struct {
	SessionID string         `json:"session_id"`
	Proxy     string         `json:"proxy"`
	Count     int            `json:"count"`
	Cookies   []restoreCookie `json:"cookies"`
}

func (h *RestoreHandler) Restore(w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	if req.Proxy == "" {
		writeError(w, http.StatusBadRequest, "proxy is required")
		return
	}

	var exists int
	err := h.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE id = ?", req.SessionID).Scan(&exists)
	if err != nil || exists == 0 {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	rows, err := h.db.Query(
		"SELECT domain, name, value, path FROM cookies WHERE session_id = ?",
		req.SessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query cookies")
		return
	}
	defer rows.Close()

	cookies := make([]restoreCookie, 0)
	for rows.Next() {
		var c db.Cookie
		if rows.Scan(&c.Domain, &c.Name, &c.Value, &c.Path) != nil {
			continue
		}
		cookies = append(cookies, restoreCookie{
			Domain: c.Domain,
			Name:   c.Name,
			Value:  c.Value,
			Path:   c.Path,
		})
	}

	writeJSON(w, http.StatusOK, restoreResponse{
		SessionID: req.SessionID,
		Proxy:     req.Proxy,
		Count:     len(cookies),
		Cookies:   cookies,
	})
}
