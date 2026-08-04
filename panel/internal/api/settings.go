package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"zialfi-panel/internal/db"
)

type SettingsHandler struct {
	db        *sql.DB
	provider     db.ProviderType
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

func NewSettingsHandler(db *sql.DB, jwtSecret string, provider db.ProviderType) *SettingsHandler {
	return &SettingsHandler{db: db, jwtSecret: jwtSecret, provider: provider}
}

func (h *SettingsHandler) Get(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(h.db, h.provider, "SELECT key, value FROM settings")
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

	auditRows, err := db.Query(h.db, h.provider, 
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
	claims, ok := getClaims(r)
	if !ok || claims.Role != "admin" {
		writeError(w, http.StatusForbidden, "admin access required")
		return
	}

	var updates map[string]string
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	for k, v := range updates {
		_, err := db.Exec(h.db, h.provider, 
			"INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
			k, v,
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update setting: "+k)
			return
		}
	}

	LogAudit(h.db, claims.UserID, "settings.update", "updated settings", extractIP(r))

	if h.onUpdate != nil {
		h.onUpdate()
	}

	rows, err := db.Query(h.db, h.provider, "SELECT key, value FROM settings")
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
