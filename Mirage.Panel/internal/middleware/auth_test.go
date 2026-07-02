package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/user/mirage-panel/internal/auth"
	"github.com/user/mirage-panel/internal/middleware"
)

func TestAuth_MissingHeader(t *testing.T) {
	m := middleware.Auth("secret")
	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuth_WrongFormat(t *testing.T) {
	m := middleware.Auth("secret")
	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Basic somecreds")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuth_InvalidJWT(t *testing.T) {
	m := middleware.Auth("secret")
	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuth_ExpiredJWT(t *testing.T) {
	claims := &auth.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
		UserID: "user-1",
		Role:   "admin",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	m := middleware.Auth("secret")
	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestAuth_ValidJWT(t *testing.T) {
	tokenStr, _, err := auth.GenerateToken("user-42", "admin", "secret")
	if err != nil {
		t.Fatal(err)
	}

	m := middleware.Auth("secret")
	var called bool
	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		claims := middleware.ClaimsFromContext(r.Context())
		if claims == nil {
			t.Error("expected claims in context")
		} else if claims.UserID != "user-42" {
			t.Errorf("expected UserID 'user-42', got %q", claims.UserID)
		}
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler was not called")
	}
}

func TestAuth_SkipPath(t *testing.T) {
	m := middleware.Auth("secret", "/api/auth/login", "/health")
	var called bool
	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler should be called for skip path")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	claims := middleware.ClaimsFromContext(req.Context())
	if claims != nil {
		t.Error("expected nil claims for skipped path")
	}
}

func TestAuth_ClaimsFromContext_NoClaims(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	claims := middleware.ClaimsFromContext(req.Context())
	if claims != nil {
		t.Error("expected nil claims when none in context")
	}
}
