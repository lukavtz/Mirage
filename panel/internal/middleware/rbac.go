package middleware

import (
	"net/http"
)

// Permission matrix: role → set of allowed permissions.
var rolePermissions = map[string]map[string]bool{
	"admin": {
		"view_sessions":    true,
		"reveal_passwords": true,
		"lock_sessions":    true,
		"download_logs":    true,
		"manage_team":      true,
		"manage_settings":  true,
		"view_activity":    true,
		"view_stats_link":  true,
	},
	"checker": {
		"view_sessions":    true,
		"reveal_passwords": true,
		"lock_sessions":    true,
	},
	"worker": {
		"view_sessions": true,
		"download_logs": true,
	},
	"viewer": {
		"view_sessions": true,
	},
	"traffer": {
		"view_stats_link": true,
		"download_logs":   true,
	},
}

func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
				return
			}

			for _, role := range roles {
				if claims.Role == role {
					next.ServeHTTP(w, r)
					return
				}
			}

			writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient permissions"})
		})
	}
}

// RequirePermission returns middleware that checks the user's role has the
// named permission according to the rolePermissions matrix.
func RequirePermission(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
				return
			}

			perms, ok := rolePermissions[claims.Role]
			if !ok || !perms[perm] {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient permissions"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HasPermission checks if a role has a given permission without creating
// middleware — useful for inline checks inside handlers.
func HasPermission(role, perm string) bool {
	perms, ok := rolePermissions[role]
	return ok && perms[perm]
}
