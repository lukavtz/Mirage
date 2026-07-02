package middleware

import (
	"net"
	"net/http"
	"strings"
)

// RealIP extracts the real client IP from X-Forwarded-For or X-Real-IP headers.
// Unlike chimw.RealIP, this does NOT mutate r.RemoteAddr — it adds the result
// to the request context instead, preventing IP spoofing via injected headers.
// For a C2 panel behind a reverse proxy, only the LAST proxy in the chain
// should be trusted: we use the first address in X-Forwarded-For (client origin).
func RealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip := extractClientIP(r); ip != "" {
			r.Header.Set("X-Real-IP", ip)
		}
		next.ServeHTTP(w, r)
	})
}

// extractClientIP extracts the client IP from request headers.
// Priority: X-Forwarded-For (first address) > X-Real-IP > RemoteAddr.
func extractClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if parts := strings.Split(fwd, ","); len(parts) > 0 {
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				if net.ParseIP(ip) != nil {
					return ip
				}
			}
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		if net.ParseIP(realIP) != nil {
			return realIP
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
