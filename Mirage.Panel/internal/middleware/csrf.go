package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"sync"
	"time"
)

type csrfStore struct {
	mu    sync.Mutex
	valid map[string]time.Time
}

var csrfTokens = &csrfStore{valid: make(map[string]time.Time)}

func init() {
	go csrfTokens.cleanupLoop()
}

func (s *csrfStore) cleanupLoop() {
	t := time.NewTicker(15 * time.Minute)
	for range t.C {
		s.mu.Lock()
		now := time.Now()
		for tok, exp := range s.valid {
			if now.After(exp) {
				delete(s.valid, tok)
			}
		}
		s.mu.Unlock()
	}
}

func (s *csrfStore) generate() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	s.valid[tok] = time.Now().Add(1 * time.Hour)
	s.mu.Unlock()
	return tok
}

func (s *csrfStore) validate(tok string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.valid[tok]
	if !ok || time.Now().After(exp) {
		return false
	}
	delete(s.valid, tok)
	return true
}

func CSRFToken(w http.ResponseWriter) string {
	tok := csrfTokens.generate()
	w.Header().Set("X-CSRF-Token", tok)
	return tok
}

func CSRFProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		if r.Header.Get("Authorization") != "" {
			next.ServeHTTP(w, r)
			return
		}

		tok := r.Header.Get("X-CSRF-Token")
		if tok == "" {
			http.Error(w, `{"error":"CSRF token required"}`, http.StatusForbidden)
			return
		}

		if !csrfTokens.validate(tok) {
			http.Error(w, `{"error":"invalid or expired CSRF token"}`, http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
