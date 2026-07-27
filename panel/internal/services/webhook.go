package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type WebhookPayload struct {
	SessionID   string `json:"session_id"`
	CountryCode string `json:"country_code"`
	Passwords   int    `json:"passwords"`
	Cookies     int    `json:"cookies"`
	Cards       int    `json:"cards"`
	Wallets     int    `json:"wallets"`
	Files       int    `json:"files"`
	Os          string `json:"os"`
	IP          string `json:"ip"`
	BuildID     string `json:"build_id"`
	BuildTag    string `json:"build_tag"`
}

func isSafeWebhookURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return false
		}
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return !(ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate())
	}
	return !strings.HasSuffix(strings.ToLower(host), ".local")
}

func SendWebhookNotification(rawURL string, payload WebhookPayload) error {
	if !isSafeWebhookURL(rawURL) {
		return fmt.Errorf("webhook url not allowed: %s", rawURL)
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	resp, err := http.Post(rawURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
