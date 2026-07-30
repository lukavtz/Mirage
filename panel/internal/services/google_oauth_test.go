package services_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"zialfi-panel/internal/services"
)

func TestExchangeRefreshToken_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.FormValue("grant_type") != "refresh_token" {
			t.Errorf("grant_type = %q", r.FormValue("grant_type"))
		}
		if r.FormValue("client_id") != "test-client" {
			t.Errorf("client_id = %q", r.FormValue("client_id"))
		}
		if r.FormValue("client_secret") != "test-secret" {
			t.Errorf("client_secret = %q", r.FormValue("client_secret"))
		}
		if r.FormValue("refresh_token") != "test-refresh" {
			t.Errorf("refresh_token = %q", r.FormValue("refresh_token"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "abc",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	services.GoogleOAuthURL = srv.URL + "/token"

	token, expiry, err := services.ExchangeRefreshToken("test-refresh", "test-client", "test-secret")
	if err != nil {
		t.Fatal(err)
	}
	if token != "abc" {
		t.Errorf("token = %q, want %q", token, "abc")
	}
	if expiry.IsZero() {
		t.Error("expected non-zero expiry")
	}
}

func TestExchangeRefreshToken_Failure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "invalid_grant",
		})
	}))
	defer srv.Close()

	services.GoogleOAuthURL = srv.URL + "/token"

	_, _, err := services.ExchangeRefreshToken("bad-token", "client", "secret")
	if err == nil {
		t.Fatal("expected error for 400 response")
	}
}

func TestExchangeRefreshToken_InvalidResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{invalid json`))
	}))
	defer srv.Close()

	services.GoogleOAuthURL = srv.URL + "/token"

	_, _, err := services.ExchangeRefreshToken("token", "client", "secret")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}
