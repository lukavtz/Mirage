package middleware

import (
	"testing"
	"time"
)

func TestAPIKeyLimiterAllow_Reset(t *testing.T) {
	keyHash := "test-hash-reset"
	if !keyLimiters.allow(keyHash, 5) {
		t.Fatal("first call should be allowed")
	}

	// Force expiry, then the counter must reset and grant again.
	keyLimiters.mu.Lock()
	entry := keyLimiters.entries[keyHash]
	entry.mu.Lock()
	entry.resetAt = time.Now().Add(-time.Minute)
	entry.mu.Unlock()
	keyLimiters.mu.Unlock()

	for i := 0; i < 5; i++ {
		if !keyLimiters.allow(keyHash, 5) {
			t.Fatalf("call %d after reset should be allowed", i+1)
		}
	}
	if keyLimiters.allow(keyHash, 5) {
		t.Error("call beyond max after reset should be denied")
	}
}