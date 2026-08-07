package middleware

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"net/http"
	"sync"
	"time"

	"zialfi-panel/internal/auth"
	dbutil "zialfi-panel/internal/db"
)

type apiKeyEntry struct {
	count   int
	resetAt time.Time
	mu      sync.Mutex
}

type apiKeyLimiter struct {
	entries map[string]*apiKeyEntry
	mu      sync.Mutex
}

var keyLimiters = &apiKeyLimiter{entries: make(map[string]*apiKeyEntry)}

type apikeyContextKey string

const apiKeyCtxKey apikeyContextKey = "apikey.info"

func APIKeyAuth(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			apiKey := r.Header.Get("X-API-Key")
			if apiKey == "" {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "API key required"})
				return
			}

			hash := sha256.Sum256([]byte(apiKey))
			keyHash := fmt.Sprintf("%x", hash)

			var userID, scope string
			var rateLimit int
			err := dbutil.QueryRow(db,
				"SELECT user_id, scope, rate_limit FROM api_keys WHERE key_hash = ?",
				keyHash,
			).Scan(&userID, &scope, &rateLimit)
			if err != nil {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid API key"})
				return
			}

			if !keyLimiters.allow(keyHash, rateLimit) {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "API key rate limit exceeded"})
				return
			}

			dbutil.Exec(db, "UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_hash = ?", keyHash)

			claims := &auth.Claims{
				UserID: userID,
				Role:   "apikey",
			}
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			ctx = context.WithValue(ctx, apiKeyCtxKey, scope)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (l *apiKeyLimiter) allow(keyHash string, maxRate int) bool {
	l.mu.Lock()
	entry, exists := l.entries[keyHash]
	if !exists {
		entry = &apiKeyEntry{resetAt: time.Now().Add(time.Minute)}
		l.entries[keyHash] = entry
	}
	l.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()
	if now.After(entry.resetAt) {
		entry.count = 0
		entry.resetAt = now.Add(time.Minute)
	}

	entry.count++
	return entry.count <= maxRate
}
