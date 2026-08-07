package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCSRFToken_SetsHeader(t *testing.T) {
	w := httptest.NewRecorder()
	tok := CSRFToken(w)
	if tok == "" {
		t.Fatal("expected non-empty token")
	}
	if got := w.Header().Get("X-CSRF-Token"); got != tok {
		t.Errorf("header X-CSRF-Token = %q, want %q", got, tok)
	}
	if !csrfTokens.validate(tok) {
		t.Error("issued token should validate")
	}
}

func TestCSRFToken_Validate_SingleUse(t *testing.T) {
	tok := csrfTokens.generate()
	if !csrfTokens.validate(tok) {
		t.Fatal("fresh token should validate")
	}
	if csrfTokens.validate(tok) {
		t.Error("token should be single-use (consumed on first validate)")
	}
}

func TestCSRFToken_Validate_Unknown(t *testing.T) {
	if csrfTokens.validate("no-such-token") {
		t.Error("unknown token should not validate")
	}
}

func TestCSRFToken_Validate_Expired(t *testing.T) {
	tok := csrfTokens.generate()
	csrfTokens.mu.Lock()
	csrfTokens.valid[tok] = time.Now().Add(-time.Hour)
	csrfTokens.mu.Unlock()
	if csrfTokens.validate(tok) {
		t.Error("expired token should not validate")
	}
}

func TestIsPublicPath(t *testing.T) {
	if !isPublicPath("/api/auth/login") {
		t.Error("/api/auth/login should be public")
	}
	if !isPublicPath("/API/AUTH/LOGIN") {
		t.Error("public path check should be case-insensitive")
	}
	if isPublicPath("/api/other") {
		t.Error("/api/other should not be public")
	}
}

func TestCSRFProtect_SafeMethodsPass(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/api/anything", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: expected 200, got %d", method, rec.Code)
		}
	}
}

func TestCSRFProtect_APIKeyExempt(t *testing.T) {
	handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/log", nil)
	req.Header.Set("X-API-Key", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for 64-char API key, got %d", rec.Code)
	}
}

func TestCSRFProtect_PublicPathExempt(t *testing.T) {
	handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for public path, got %d", rec.Code)
	}
}

func TestCSRFProtect_MissingToken(t *testing.T) {
	handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/private", nil)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestCSRFProtect_InvalidToken(t *testing.T) {
	handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/private", nil)
	req.Header.Set("X-CSRF-Token", "bogus")
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestCSRFProtect_ValidToken(t *testing.T) {
	tok := csrfTokens.generate()
	handler := CSRFProtect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/private", nil)
	req.Header.Set("X-CSRF-Token", tok)
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}
