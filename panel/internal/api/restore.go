package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/services"
)

type RestoreHandler struct {
	db *sql.DB
}

func NewRestoreHandler(db *sql.DB) *RestoreHandler {
	return &RestoreHandler{db: db}
}

type restoreRequest struct {
	SessionID   string                `json:"session_id"`
	ProxyConfig *services.ProxyConfig `json:"proxy_config"`
	Proxy       string                `json:"proxy"`
}

type restoreCookie struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Value  string `json:"value"`
	Path   string `json:"path"`
}

type restoreResponse struct {
	SessionID string          `json:"session_id"`
	Proxy     string          `json:"proxy"`
	Count     int             `json:"count"`
	Cookies   []restoreCookie `json:"cookies"`
}

type cookieUploadRequest struct {
	SessionID   string                `json:"session_id"`
	Cookies     []restoreCookie       `json:"cookies"`
	ProxyConfig *services.ProxyConfig `json:"proxy_config"`
}

type restoreSessionResponse struct {
	ID          string `json:"id"`
	SessionID   string `json:"session_id"`
	Status      string `json:"status"`
	AccessToken string `json:"access_token,omitempty"`
	Error       string `json:"error,omitempty"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

func (h *RestoreHandler) Restore(w http.ResponseWriter, r *http.Request) {
	var req restoreRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	proxyStr := req.Proxy
	if req.ProxyConfig != nil {
		proxyStr = req.ProxyConfig.Addr()
	}
	if proxyStr == "" {
		writeError(w, http.StatusBadRequest, "proxy is required")
		return
	}

	var exists int
	err := db.QueryRow(h.db, "SELECT COUNT(*) FROM sessions WHERE id = ?", req.SessionID).Scan(&exists)
	if err != nil || exists == 0 {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	if !sessionOwnedBy(h.db, r, req.SessionID) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	rows, err := db.Query(h.db, "SELECT domain, name, value, path FROM cookies WHERE session_id = ?",
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
		Proxy:     proxyStr,
		Count:     len(cookies),
		Cookies:   cookies,
	})
}

func (h *RestoreHandler) UploadCookies(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req cookieUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "session_id is required")
		return
	}
	if len(req.Cookies) == 0 {
		writeError(w, http.StatusBadRequest, "cookies are required")
		return
	}

	if !sessionOwnedBy(h.db, r, req.SessionID) {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	proxyJSON := ""
	if req.ProxyConfig != nil {
		data, _ := json.Marshal(req.ProxyConfig)
		proxyJSON = string(data)
	}

	cookiesJSON, _ := json.Marshal(req.Cookies)
	id := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	_, err := db.Exec(h.db, `INSERT INTO restore_sessions (id, user_id, session_id, cookies_json, proxy_config, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 'processing', ?, ?)`,
		id, claims.UserID, req.SessionID, string(cookiesJSON), proxyJSON, now, now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create restore session")
		return
	}

	go func() {
		defer func() {
			if r := recover(); r != nil {
				now := time.Now().UTC().Format(time.RFC3339)
				db.Exec(h.db, `UPDATE restore_sessions SET status = 'failed', error = 'internal panic', updated_at = ? WHERE id = ?`,
					now, id)
			}
		}()
		h.processRestore(id, req, proxyJSON)
	}()

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":     id,
		"status": "processing",
	})
}

func (h *RestoreHandler) processRestore(id string, req cookieUploadRequest, proxyJSON string) {
	var proxyConfig services.ProxyConfig
	if proxyJSON != "" {
		json.Unmarshal([]byte(proxyJSON), &proxyConfig)
	}

	accessToken := ""
	errMsg := ""

	if proxyConfig.Host != "" {
		conn, err := services.ConnectViaSOCKS5("oauth2.googleapis.com", 443, proxyConfig)
		if err != nil {
			errMsg = "proxy connection failed: " + err.Error()
		} else {
			conn.Close()
		}
	}

	status := "completed"
	if errMsg != "" {
		status = "failed"
	}

	now := time.Now().UTC().Format(time.RFC3339)
	db.Exec(h.db, `UPDATE restore_sessions SET status = ?, access_token = ?, error = ?, updated_at = ? WHERE id = ?`,
		status, accessToken, errMsg, now, id)
}

func (h *RestoreHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	query := `SELECT id, session_id, status, access_token, error, created_at, updated_at
		FROM restore_sessions WHERE user_id = ? ORDER BY created_at DESC`
	args := []any{claims.UserID}

	if claims.Role == "admin" {
		query = `SELECT id, session_id, status, access_token, error, created_at, updated_at
			FROM restore_sessions ORDER BY created_at DESC`
		args = nil
	}

	rows, err := db.Query(h.db, query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query restore sessions")
		return
	}
	defer rows.Close()

	sessions := make([]restoreSessionResponse, 0)
	for rows.Next() {
		var s restoreSessionResponse
		if err := rows.Scan(&s.ID, &s.SessionID, &s.Status, &s.AccessToken, &s.Error, &s.CreatedAt, &s.UpdatedAt); err != nil {
			continue
		}
		sessions = append(sessions, s)
	}

	writeJSON(w, http.StatusOK, sessions)
}

func (h *RestoreHandler) SessionStatus(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := chi.URLParam(r, "id")

	var s restoreSessionResponse
	var userID string
	err := db.QueryRow(h.db, `SELECT id, session_id, user_id, status, COALESCE(access_token,''), COALESCE(error,''), created_at, updated_at
		 FROM restore_sessions WHERE id = ?`, id).Scan(&s.ID, &s.SessionID, &userID, &s.Status, &s.AccessToken, &s.Error, &s.CreatedAt, &s.UpdatedAt)

	if err != nil {
		writeError(w, http.StatusNotFound, "restore session not found")
		return
	}

	if userID != "" && userID != claims.UserID && claims.Role != "admin" {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	if claims.Role != "admin" {
		s.AccessToken = ""
	}

	writeJSON(w, http.StatusOK, s)
}
