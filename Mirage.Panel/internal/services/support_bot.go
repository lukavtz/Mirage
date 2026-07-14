package services

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type SupportBot struct {
	botToken string
	db       *sql.DB
	apiBase  string
}

type tgUpdate struct {
	Message *tgMessage `json:"message"`
}

type tgMessage struct {
	Chat tgChat `json:"chat"`
	From tgFrom `json:"from"`
	Text string `json:"text"`
}

type tgChat struct {
	ID int64 `json:"id"`
}

type tgFrom struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

type tgSend struct {
	ChatID int64  `json:"chat_id"`
	Text   string `json:"text"`
}

func NewSupportBot(token string, db *sql.DB) *SupportBot {
	return &SupportBot{
		botToken: token,
		db:       db,
		apiBase:  "https://api.telegram.org/bot" + token,
	}
}

func (b *SupportBot) HandleUpdate(body []byte) {
	var upd tgUpdate
	if err := json.Unmarshal(body, &upd); err != nil || upd.Message == nil {
		return
	}
	msg := upd.Message
	text := strings.TrimSpace(msg.Text)

	switch {
	case text == "/start":
		b.send(msg.Chat.ID, welcomeText())
	case strings.HasPrefix(text, "/buy"):
		b.handleBuy(msg)
	case strings.HasPrefix(text, "/license"):
		b.handleLicense(msg)
	case text == "/help":
		b.send(msg.Chat.ID, helpText())
	default:
		b.send(msg.Chat.ID, "Unknown command. Send /help for available commands.")
	}
}

func (b *SupportBot) handleBuy(msg *tgMessage) {
	parts := strings.Fields(msg.Text)
	if len(parts) < 2 {
		b.send(msg.Chat.ID, "Usage: /buy {tier}\n\nTiers: starter ($70/mo), pro ($150/mo), team ($350/mo)")
		return
	}

	tier := strings.ToLower(parts[1])
	valid := map[string]bool{"starter": true, "pro": true, "team": true, "lifetime": true}
	if !valid[tier] {
		b.send(msg.Chat.ID, "Invalid tier. Choose: starter, pro, team, or lifetime.")
		return
	}

	id := uuid.New().String()
	_, err := b.db.Exec(
		`INSERT INTO sales_leads (id, telegram_id, username, tier, status) VALUES (?, ?, ?, ?, 'new')`,
		id, fmt.Sprintf("%d", msg.From.ID), msg.From.Username, tier,
	)
	if err != nil {
		slog.Error("failed to save sales lead", "err", err)
		b.send(msg.Chat.ID, "Something went wrong. Please try again later.")
		return
	}

	b.send(msg.Chat.ID, fmt.Sprintf(
		"Purchase request received for **%s** tier!\n\n"+
			"An admin will contact you shortly with payment instructions.\n\n"+
			"Reference: `%s`", tier, id[:8],
	))
}

func (b *SupportBot) handleLicense(msg *tgMessage) {
	parts := strings.Fields(msg.Text)
	if len(parts) < 2 {
		b.send(msg.Chat.ID, "Usage: /license {license_key}")
		return
	}

	key := strings.TrimSpace(parts[1])
	var userID, tier, expiresAt string
	err := b.db.QueryRow(
		"SELECT user_id, tier, COALESCE(expires_at, '') FROM purchases WHERE license_key = ?", key,
	).Scan(&userID, &tier, &expiresAt)
	if err != nil {
		b.send(msg.Chat.ID, "License key not found.")
		return
	}

	text := fmt.Sprintf("License: `%s`\nTier: **%s**\nActive: **true**", key, tier)
	if expiresAt != "" {
		text += fmt.Sprintf("\nExpires: `%s`", expiresAt)
	}
	b.send(msg.Chat.ID, text)
}

func (b *SupportBot) send(chatID int64, text string) {
	payload := tgSend{ChatID: chatID, Text: text}
	data, _ := json.Marshal(payload)

	resp, err := http.Post(b.apiBase+"/sendMessage", "application/json", bytes.NewReader(data))
	if err != nil {
		slog.Error("telegram send failed", "err", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

func (b *SupportBot) SetWebhook(url string) error {
	payload := map[string]string{"url": url}
	data, _ := json.Marshal(payload)
	resp, err := http.Post(b.apiBase+"/setWebhook", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("set webhook: %w", err)
	}
	defer resp.Body.Close()
	return nil
}

func welcomeText() string {
	return `Welcome to **Mirage Support Bot**!

We offer the following tiers:

**Starter** — $70/mo or $700 lifetime
1 bot, 1 user, API-limited

**Pro** — $150/mo or $1,500 lifetime
7 bots, 5 users, smart filters, clipper & loader modules

**Team** — $350/mo or $3,500 lifetime
15 bots, 20 users, PostgreSQL, all modules

Commands:
/buy {tier} — start purchase
/license {key} — check license status
/help — show help`
}

func helpText() string {
	return `Available commands:

/start — welcome & pricing
/buy {tier} — start a purchase (starter/pro/team/lifetime)
/license {key} — check license status
/help — this message

Need more help? Contact support@mirage.local`
}
