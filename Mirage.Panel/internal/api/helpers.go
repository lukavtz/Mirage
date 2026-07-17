package api

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/user/mirage-panel/internal/auth"
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
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if ip := net.ParseIP(realIP); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func getClaims(r *http.Request) (*auth.Claims, bool) {
	claims, ok := r.Context().Value(claimsKey).(*auth.Claims)
	return claims, ok && claims != nil
}
