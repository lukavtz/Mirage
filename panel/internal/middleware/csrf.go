package middleware

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"sync"
	"time"
)

type csrfStore struct {
	mu    sync.Mutex
	valid map[string]time.Time
}

var csrfTokens = &csrfStore{valid: make(map[string]time.Time)}

// ponytail: public paths that don't require CSRF (chicken-and-egg for login).
var csrfPublicPaths = []string{
	"/api/auth/login",
	"/api/auth/register",
	"/api/auth/2fa/verify-login",
	"/api/auth/2fa/required",
	"/api/public/stats",
	"/api/pricing",
	"/api/log",
	"/api/log/chunk",
	"/api/log/complete",
	"/api/log/ssp",
}

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

func isPublicPath(path string) bool {
	for _, p := range csrfPublicPaths {
		if strings.EqualFold(path, p) {
			return true
		}
	}
	return false
}

func CSRFProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// ponytail: CSRF protection — Bearer tokens do NOT prevent CSRF when
		// cookies carry session state. API keys (64 hex chars) are exempt because
		// they're only used by the stealer (non-browser context).
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			// Cookie-based auth is vulnerable to CSRF — require CSRF token
			// API keys (stealer context, non-browser) are exempt
		}
		if apikey := r.Header.Get("X-API-Key"); len(apikey) == 64 {
			next.ServeHTTP(w, r)
			return
		}

		if isPublicPath(r.URL.Path) {
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
