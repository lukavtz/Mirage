package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"zialfi-panel/internal/middleware"
)

func TestRateLimit_UnderLimit(t *testing.T) {
	m := middleware.RateLimit(50, time.Minute)
	var mu sync.Mutex
	var count int

	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		count++
		mu.Unlock()
	}))

	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	if count != 50 {
		t.Errorf("expected 50 calls, got %d", count)
	}
}

func TestRateLimit_ExceedsLimit(t *testing.T) {
	m := middleware.RateLimit(100, time.Minute)
	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	for i := 0; i < 100; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:54321"
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", rec.Code)
	}
}

func TestRateLimit_DifferentIPs(t *testing.T) {
	m := middleware.RateLimit(5, time.Minute)
	var mu sync.Mutex
	counters := make(map[string]int)

	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		counters[r.RemoteAddr]++
		mu.Unlock()
	}))

	ips := []string{"10.0.0.1:1000", "10.0.0.2:2000", "10.0.0.3:3000"}
	for i := 0; i < 10; i++ {
		for _, ip := range ips {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = ip
			handler.ServeHTTP(rec, req)
		}
	}

	if counters["10.0.0.1:1000"] != 5 {
		t.Errorf("expected 5 calls for 10.0.0.1 (rate limited after max), got %d", counters["10.0.0.1:1000"])
	}
	if counters["10.0.0.2:2000"] != 5 {
		t.Errorf("expected 5 calls for 10.0.0.2 (rate limited after max), got %d", counters["10.0.0.2:2000"])
	}
}

func TestRateLimit_WindowReset(t *testing.T) {
	shortWindow := 50 * time.Millisecond
	m := middleware.RateLimit(1, shortWindow)

	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1111"
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second request before reset: expected 429, got %d", rec.Code)
	}

	time.Sleep(shortWindow + 10*time.Millisecond)

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("request after window reset: expected 200, got %d", rec.Code)
	}
}

func TestRateLimit_ZeroRequests(t *testing.T) {
	m := middleware.RateLimit(0, time.Minute)
	handler := m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:1111"
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 for zero limit, got %d", rec.Code)
	}
}

// ExtractIP now uses RemoteAddr only — X-Forwarded-For and X-Real-IP are NOT trusted.

func TestExtractIP_IgnoresXForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18, 150.172.238.178")
	got := middleware.ExtractIP(req)
	if got != "10.0.0.1" {
		t.Errorf("expected RemoteAddr 10.0.0.1, got %q", got)
	}
}

func TestExtractIP_IgnoresXForwardedForSingle(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	got := middleware.ExtractIP(req)
	if got != "10.0.0.1" {
		t.Errorf("expected RemoteAddr 10.0.0.1, got %q", got)
	}
}

func TestExtractIP_IgnoresXRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Real-IP", "198.51.100.77")
	got := middleware.ExtractIP(req)
	if got != "10.0.0.1" {
		t.Errorf("expected RemoteAddr 10.0.0.1, got %q", got)
	}
}

func TestExtractIP_IgnoresBothXFFAndRealIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:54321"
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	req.Header.Set("X-Real-IP", "198.51.100.77")
	got := middleware.ExtractIP(req)
	if got != "10.0.0.1" {
		t.Errorf("expected RemoteAddr 10.0.0.1, got %q", got)
	}
}

func TestExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.42:12345"
	got := middleware.ExtractIP(req)
	if got != "192.168.1.42" {
		t.Errorf("expected 192.168.1.42, got %q", got)
	}
}

func TestExtractIP_RemoteAddrNoPort(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.42"
	got := middleware.ExtractIP(req)
	if got != "192.168.1.42" {
		t.Errorf("expected 192.168.1.42, got %q", got)
	}
}

func TestExtractIP_IPv6(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "[::1]:12345"
	got := middleware.ExtractIP(req)
	if got != "::1" {
		t.Errorf("expected ::1, got %q", got)
	}
}
