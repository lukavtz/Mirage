package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"zialfi-panel/internal/middleware"
)

func TestRealIP_SetsHeaderFromRemoteAddr(t *testing.T) {
	var got string
	handler := middleware.RealIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Real-IP")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	handler.ServeHTTP(rec, req)
	if got != "203.0.113.7" {
		t.Errorf("expected X-Real-IP from RemoteAddr, got %q", got)
	}
}

func TestRealIP_DoesNotTrustXFF(t *testing.T) {
	var got string
	handler := middleware.RealIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Real-IP")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	req.Header.Set("X-Forwarded-For", "198.51.100.1")
	req.Header.Set("X-Real-IP", "198.51.100.1")
	handler.ServeHTTP(rec, req)
	if got != "203.0.113.7" {
		t.Errorf("RealIP must ignore spoofable headers, got %q", got)
	}
}

func TestRealIP_EmptyRemoteAddr(t *testing.T) {
	var got string
	handler := middleware.RealIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Real-IP")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = ""
	handler.ServeHTTP(rec, req)
	if got != "" {
		t.Errorf("expected no X-Real-IP for empty RemoteAddr, got %q", got)
	}
}

func TestRealIP_RemoteAddrWithoutPort(t *testing.T) {
	var got string
	handler := middleware.RealIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Real-IP")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.9"
	handler.ServeHTTP(rec, req)
	if got != "198.51.100.9" {
		t.Errorf("expected bare IP fallback, got %q", got)
	}
}

func TestRealIP_StripsInvalidPort(t *testing.T) {
	var got string
	handler := middleware.RealIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Real-IP")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.9:notaport"
	handler.ServeHTTP(rec, req)
	if got != "198.51.100.9" {
		t.Errorf("expected port stripped, got %q", got)
	}
}