package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/db"
)

type TeamHandler struct {
	db *sql.DB
	provider     db.ProviderType
}

func NewTeamHandler(db *sql.DB, provider db.ProviderType) *TeamHandler {
	return &TeamHandler{db: db, provider: provider}
}

type teamMember struct {
	ID        string  `json:"id"`
	Username  string  `json:"username"`
	Role      string  `json:"role"`
	Status    string  `json:"status"`
	LastLogin *string `json:"last_login"`
	Sessions  int     `json:"sessions"`
	CreatedAt string  `json:"created_at"`
}

func (h *TeamHandler) List(w http.ResponseWriter, r *http.Request) {
	roleFilter := r.URL.Query().Get("role")
	query := `
		SELECT u.id, u.username, u.role, u.created_at,
			(SELECT MAX(created_at) FROM auth_sessions WHERE user_id = u.id) as last_login,
			(SELECT COUNT(*) FROM auth_sessions WHERE user_id = u.id) as session_count
		FROM users u`
	args := []any{}
	if roleFilter != "" {
		query += " WHERE u.role = ?"
		args = append(args, roleFilter)
	}
	query += " ORDER BY u.created_at DESC"

	rows, err := db.Query(h.db, h.provider, query, args...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query team")
		return
	}
	defer rows.Close()

	members := make([]teamMember, 0)
	for rows.Next() {
		var m teamMember
		if err := rows.Scan(&m.ID, &m.Username, &m.Role, &m.CreatedAt, &m.LastLogin, &m.Sessions); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan member")
			return
		}
		m.Status = "offline"
		if m.LastLogin != nil {
			var lastActive sql.NullString
			err := db.QueryRow(h.db, h.provider, "SELECT MAX(last_active_at) FROM auth_sessions WHERE user_id = ?", m.ID).Scan(&lastActive)
			if err == nil && lastActive.Valid {
				parsed, err := time.Parse("2006-01-02 15:04:05", lastActive.String)
				if err == nil && time.Since(parsed) < 5*time.Minute {
					m.Status = "online"
				}
			}
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to iterate")
		return
	}

	writeJSON(w, http.StatusOK, members)
}

func (h *TeamHandler) ChangeRole(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	var req struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	validRoles := map[string]bool{"admin": true, "checker": true, "worker": true, "viewer": true, "traffer": true}
	if !validRoles[req.Role] {
		writeError(w, http.StatusBadRequest, "invalid role")
		return
	}

	result, err := db.Exec(h.db, h.provider, "UPDATE users SET role = ? WHERE id = ?", req.Role, userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update role")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	claims, ok := getClaims(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	LogAudit(h.db, claims.UserID, "team.change_role", "Changed user "+userID+" to "+req.Role, extractIP(r))

	writeJSON(w, http.StatusOK, map[string]string{"message": "role updated"})
}

func (h *TeamHandler) Remove(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	claims, ok := getClaims(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	if userID == claims.UserID {
		writeError(w, http.StatusBadRequest, "cannot remove yourself")
		return
	}

	result, err := db.Exec(h.db, h.provider, "DELETE FROM users WHERE id = ?", userID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to remove user")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	LogAudit(h.db, claims.UserID, "team.remove", "Removed user "+userID, extractIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"message": "user removed"})
}

func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
