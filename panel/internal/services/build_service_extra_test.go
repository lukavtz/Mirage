package services_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"zialfi-panel/internal/services"
)

func TestTelegram_SendLog_RetryThenSuccess(t *testing.T) {
	var attempts int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&attempts, 1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			io.Copy(io.Discard, r.Body)
			r.Body.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer ts.Close()

	proxy := services.NewTelegramProxy()
	proxy.BaseURL = ts.URL

	err := proxy.SendLog("test123", "12345", []byte("log data"), "log.txt", "test caption")
	if err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(&attempts); n != 3 {
		t.Errorf("expected 3 attempts, got %d", n)
	}
}

func TestTelegram_SendLog_AllRetriesFail(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}))
	defer ts.Close()

	proxy := services.NewTelegramProxy()
	proxy.BaseURL = ts.URL

	err := proxy.SendLog("test123", "12345", []byte("log data"), "log.txt", "test caption")
	if err == nil {
		t.Fatal("expected error after all retries")
	}
}

func TestTelegram_TestToken_NonOKStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"ok":false,"description":"Unauthorized"}`)
	}))
	defer ts.Close()

	proxy := services.NewTelegramProxy()
	proxy.BaseURL = ts.URL

	err := proxy.TestToken("invalid-token")
	if err == nil {
		t.Fatal("expected error for 401")
	}
}

func TestTelegram_TestToken_OkFalse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"ok":false}`)
	}))
	defer ts.Close()

	proxy := services.NewTelegramProxy()
	proxy.BaseURL = ts.URL

	err := proxy.TestToken("token")
	if err == nil {
		t.Fatal("expected error for ok=false")
	}
}

func TestTelegram_TestToken_NetworkError(t *testing.T) {
	proxy := services.NewTelegramProxy()
	proxy.BaseURL = "http://localhost:1"

	err := proxy.TestToken("token")
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestTelegram_SendLog_NetworkError(t *testing.T) {
	proxy := services.NewTelegramProxy()
	proxy.BaseURL = "http://localhost:1"

	err := proxy.SendLog("test123", "12345", []byte("log data"), "log.txt", "test caption")
	if err == nil {
		t.Fatal("expected network error")
	}
}
