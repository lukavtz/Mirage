package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/user/mirage-panel/internal/auth"
)

type SettingsHandler struct {
	db        *sql.DB
	jwtSecret string
	onUpdate  func()
}

type AuditEntry struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id,omitempty"`
	Action    string `json:"action"`
	Details   string `json:"details,omitempty"`
	IP        string `json:"ip,omitempty"`
	CreatedAt string `json:"created_at"`
}

type SettingsResponse struct {
	Settings map[string]string `json:"settings"`
	Audit    []AuditEntry      `json:"audit"`
}

func NewSettingsHandler(db *sql.DB, jwtSecret string) *SettingsHandler {
	return &SettingsHandler{db: db, jwtSecret: jwtSecret}
}

func (h *SettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT key, value FROM settings")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query settings")
		return
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			settings[k] = v
		}
	}

	auditRows, err := h.db.Query(
		"SELECT id, COALESCE(user_id,''), action, COALESCE(details,''), COALESCE(ip,''), created_at FROM audit_log ORDER BY created_at DESC LIMIT 50",
	)
	if err != nil {
		writeJSON(w, http.StatusOK, SettingsResponse{Settings: settings, Audit: []AuditEntry{}})
		return
	}
	defer auditRows.Close()

	audit := make([]AuditEntry, 0, 50)
	for auditRows.Next() {
		var e AuditEntry
		if auditRows.Scan(&e.ID, &e.UserID, &e.Action, &e.Details, &e.IP, &e.CreatedAt) == nil {
			audit = append(audit, e)
		}
	}

	writeJSON(w, http.StatusOK, SettingsResponse{Settings: settings, Audit: audit})
}

func (h *SettingsHandler) Update(w http.ResponseWriter, r *http.Request) {
	var updates map[string]string
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	for k, v := range updates {
		_, err := h.db.Exec(
			"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
			k, v,
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update setting: "+k)
			return
		}
	}

	claims := r.Context().Value(claimsKey)
	userID := ""
	if c, ok := claims.(*auth.Claims); ok {
		userID = c.UserID
	}
	LogAudit(h.db, userID, "settings.update", "updated settings", extractIP(r))

	if h.onUpdate != nil {
		h.onUpdate()
	}

	rows, err := h.db.Query("SELECT key, value FROM settings")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query settings")
		return
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		if rows.Scan(&k, &v) == nil {
			settings[k] = v
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{"settings": settings})
}

func (h *SettingsHandler) SetOnUpdate(fn func()) {
	h.onUpdate = fn
}
