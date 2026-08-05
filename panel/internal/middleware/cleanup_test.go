package middleware

import (
	"testing"
	"time"
)

func TestCSRFPruneExpired(t *testing.T) {
	// Generate an expired token first (before locking).
	expiredTok := csrfTokens.generate()
	csrfTokens.mu.Lock()
	csrfTokens.valid[expiredTok] = time.Now().Add(-time.Hour)
	csrfTokens.mu.Unlock()

	// Now generate a current token.
	current := csrfTokens.generate()

	csrfTokens.pruneExpired()

	// Expired token should be gone.
	csrfTokens.mu.Lock()
	_, ok := csrfTokens.valid[expiredTok]
	csrfTokens.mu.Unlock()
	if ok {
		t.Error("expired token should have been pruned")
	}

	// The current token should still be valid.
	if !csrfTokens.validate(current) {
		t.Error("current token should still validate after pruning")
	}
}

func TestRateLimitPruneExpired(t *testing.T) {
	rl := &rateLimiter{
		entries: make(map[string]*rateEntry),
	}

	rl.entries["current"] = &rateEntry{resetAt: time.Now().Add(time.Hour)}
	rl.entries["expired"] = &rateEntry{resetAt: time.Now().Add(-time.Hour)}

	rl.pruneExpired()

	if _, ok := rl.entries["expired"]; ok {
		t.Error("expired entry should have been pruned")
	}
	if _, ok := rl.entries["current"]; !ok {
		t.Error("current entry should not have been pruned")
	}
}
