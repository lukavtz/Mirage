package api

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/db"
)

type SessionMgmtHandler struct {
	db *sql.DB
	provider db.ProviderType
}

type AuthSessionItem struct {
	ID           string `json:"id"`
	UserID       string `json:"user_id"`
	Device       string `json:"device"`
	OS           string `json:"os"`
	Browser      string `json:"browser"`
	IP           string `json:"ip"`
	Location     string `json:"location,omitempty"`
	LastActiveAt string `json:"last_active_at"`
	CreatedAt    string `json:"created_at"`
}

func NewSessionMgmtHandler(db *sql.DB, provider db.ProviderType) *SessionMgmtHandler {
	return &SessionMgmtHandler{db: db, provider: provider}
}

func (h *SessionMgmtHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	rows, err := db.Query(h.db, h.provider, `
		SELECT id, user_id, device, os, browser, ip, location, last_active_at, created_at
		FROM auth_sessions WHERE user_id = ? ORDER BY last_active_at DESC`, claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}
	defer rows.Close()

	items := make([]AuthSessionItem, 0)
	for rows.Next() {
		var item AuthSessionItem
		if err := rows.Scan(&item.ID, &item.UserID, &item.Device, &item.OS, &item.Browser, &item.IP, &item.Location, &item.LastActiveAt, &item.CreatedAt); err != nil {
			continue
		}
		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{"sessions": items})
}

func (h *SessionMgmtHandler) Terminate(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	sessionID := chi.URLParam(r, "id")

	result, err := db.Exec(h.db, h.provider, "DELETE FROM auth_sessions WHERE id = ? AND user_id = ?", sessionID, claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to terminate session")
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "session terminated"})
}

func (h *SessionMgmtHandler) TerminateAll(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	currentSessionID := claims.SessionID

	if currentSessionID != "" {
		_, err := db.Exec(h.db, h.provider, "DELETE FROM auth_sessions WHERE user_id = ? AND id != ?", claims.UserID, currentSessionID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to terminate sessions")
			return
		}
	} else {
		_, err := db.Exec(h.db, h.provider, "DELETE FROM auth_sessions WHERE user_id = ?", claims.UserID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to terminate sessions")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "other sessions terminated"})
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

func parseUserAgent(ua string) (os, browser string) {
	if ua == "" {
		return "Unknown", "Unknown"
	}

	switch {
	case strings.Contains(ua, "Windows"):
		os = "Windows"
	case strings.Contains(ua, "Mac OS X") || strings.Contains(ua, "macOS"):
		os = "macOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "iOS") || strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad"):
		os = "iOS"
	default:
		os = "Unknown"
	}

	switch {
	case strings.Contains(ua, "Chrome") && !strings.Contains(ua, "Edg") && !strings.Contains(ua, "OPR"):
		browser = "Chrome"
	case strings.Contains(ua, "Firefox"):
		browser = "Firefox"
	case strings.Contains(ua, "Safari") && !strings.Contains(ua, "Chrome"):
		browser = "Safari"
	case strings.Contains(ua, "Edg"):
		browser = "Edge"
	case strings.Contains(ua, "OPR") || strings.Contains(ua, "Opera"):
		browser = "Opera"
	default:
		browser = "Unknown"
	}

	return os, browser
}

func claimsFromCtx(r *http.Request) *auth.Claims {
	return middleware.ClaimsFromContext(r.Context())
}
