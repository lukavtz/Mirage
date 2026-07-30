package middleware

import (
	"net"
	"net/http"
	"strings"
)

// RealIP extracts the real client IP from the direct connection.
// Security: We ONLY trust RemoteAddr (the direct TCP peer) and NEVER
// X-Forwarded-For or X-Real-IP headers, which are client-controlled
// and can be spoofed. This prevents IP-based rate limiting / ban bypass.
// If behind a reverse proxy, configure the proxy to set RemoteAddr
// (e.g., HAProxy's `option forwardfor` with `source` keyword).
func RealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractClientIP(r)
		if ip != "" {
			r.Header.Set("X-Real-IP", ip)
		}
		next.ServeHTTP(w, r)
	})
}

// extractClientIP extracts the client IP from the direct connection.
// ONLY uses RemoteAddr — never trusts X-Forwarded-For or X-Real-IP headers
// because they are fully client-controlled and allow rate-limit/ban bypass.
func extractClientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && host != "" {
		if net.ParseIP(host) != nil {
			return host
		}
	}
	// Fallback: if RemoteAddr has no port
	if net.ParseIP(r.RemoteAddr) != nil {
		return r.RemoteAddr
	}
	// Last resort: strip any port
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		addr = addr[:idx]
	}
	return addr
}
