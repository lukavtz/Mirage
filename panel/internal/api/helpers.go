package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/middleware"
)

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func extractIP(r *http.Request) string {
	return middleware.ExtractIP(r)
}

func getClaims(r *http.Request) (*auth.Claims, bool) {
	claims := middleware.ClaimsFromContext(r.Context())
	return claims, claims != nil
}

func claimsUserID(r *http.Request) string {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		return ""
	}
	return claims.UserID
}

// sessionOwnedBy reports whether the caller may access the given session.
// Admins bypass ownership; other roles are limited to their own sessions.
// A nil claims value (no auth middleware on the route) means the request is
// not tenant-scoped; the AuthMiddleware guard is the only barrier then,
// matching List/Detail behavior.
func sessionOwnedBy(db *sql.DB, r *http.Request, sessionID string) bool {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		return true
	}
	if claims.Role == "admin" {
		return true
	}
	var ownerID string
	err := db.QueryRow("SELECT COALESCE(owner_id, '') FROM sessions WHERE id = ?", sessionID).Scan(&ownerID)
	if err != nil {
		return false
	}
	return ownerID == claims.UserID
}

// buildOwnedBy reports whether the caller may access the given build.
// Admins bypass ownership; other roles are limited to their own builds.
// A nil claims value (no auth middleware on the route) means the request is
// not tenant-scoped; the AuthMiddleware guard is the only barrier then,
// matching List/Detail behavior.
func buildOwnedBy(db *sql.DB, r *http.Request, buildID string) bool {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		return true
	}
	if claims.Role == "admin" {
		return true
	}
	var userID string
	err := db.QueryRow("SELECT COALESCE(user_id, '') FROM builds WHERE id = ?", buildID).Scan(&userID)
	if err != nil {
		return false
	}
	return userID == claims.UserID
}
