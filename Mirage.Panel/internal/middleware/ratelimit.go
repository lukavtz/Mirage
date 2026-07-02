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
	stopCh      chan struct{}
}

func RateLimit(maxRequests int, window time.Duration) func(http.Handler) http.Handler {
	rl := &rateLimiter{
		maxRequests: maxRequests,
		window:      window,
		entries:     make(map[string]*rateEntry),
		stopCh:      make(chan struct{}),
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

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, entry := range rl.entries {
				entry.mu.Lock()
				if now.After(entry.resetAt) {
					delete(rl.entries, ip)
				}
				entry.mu.Unlock()
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

func extractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
