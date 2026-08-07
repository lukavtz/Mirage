package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

type rateEntry struct {
	count   int
	resetAt time.Time
	mu      sync.Mutex
}

type rateLimiter struct {
	maxRequests int
	window      time.Duration
	entries     map[string]*rateEntry
	mu          sync.Mutex
}

func RateLimit(maxRequests int, window time.Duration) func(http.Handler) http.Handler {
	rl := &rateLimiter{
		maxRequests: maxRequests,
		window:      window,
		entries:     make(map[string]*rateEntry),
	}

	go rl.cleanup()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)

			rl.mu.Lock()
			entry, exists := rl.entries[ip]
			if !exists {
				entry = &rateEntry{
					count:   0,
					resetAt: time.Now().Add(rl.window),
				}
				rl.entries[ip] = entry
			}
			rl.mu.Unlock()

			entry.mu.Lock()
			now := time.Now()
			if now.After(entry.resetAt) {
				entry.count = 0
				entry.resetAt = now.Add(rl.window)
			}

			entry.count++
			if entry.count > rl.maxRequests {
				entry.mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				json.NewEncoder(w).Encode(map[string]string{"error": "rate limit exceeded"})
				return
			}
			entry.mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}

func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		rl.pruneExpired()
	}
}

func (rl *rateLimiter) pruneExpired() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, entry := range rl.entries {
		entry.mu.Lock()
		if now.After(entry.resetAt) {
			delete(rl.entries, ip)
		}
		entry.mu.Unlock()
	}
}

// ExtractIP returns the client IP from RemoteAddr only.
// X-Forwarded-For and X-Real-IP are NOT trusted — they are trivially spoofable
// and bypass rate limits + IP bans.
func ExtractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return host
}

// extractIP is the unexported alias kept for in-package callers
// (ratelimit, ban middleware) so the rename touches no call sites.
func extractIP(r *http.Request) string { return ExtractIP(r) }
