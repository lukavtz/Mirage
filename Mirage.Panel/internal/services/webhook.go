package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
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

func SendWebhookNotification(url string, payload WebhookPayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
