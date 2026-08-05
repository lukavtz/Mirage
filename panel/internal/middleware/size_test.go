package middleware_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"zialfi-panel/internal/middleware"
)

func TestRequestSizeLimit_OverLimitRejected(t *testing.T) {
	handler := middleware.RequestSizeLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for oversized request")
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, 10<<20+1)))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", rec.Code)
	}
}

func TestRequestSizeLimit_AtLimitPasses(t *testing.T) {
	var got []byte
	handler := middleware.RequestSizeLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		got = b
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, 10<<20)))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if len(got) != 10<<20 {
		t.Errorf("expected 10 MiB body readable, got %d bytes", len(got))
	}
}

func TestRequestSizeLimit_SmallBodyPasses(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	var got []byte
	handler := middleware.RequestSizeLimit(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		got = b
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if string(got) != string(body) {
		t.Errorf("expected body echoed, got %q", got)
	}
}