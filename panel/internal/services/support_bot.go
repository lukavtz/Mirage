package services

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"zialfi-panel/internal/db"
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

// SetAPIBase overrides the Telegram API base URL (for testing).
func (b *SupportBot) SetAPIBase(url string) {
	b.apiBase = url
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
	_, err := db.Exec(b.db,
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
	err := db.QueryRow(
		b.db,
		"SELECT user_id, tier, COALESCE(expires_at::text, '') FROM purchases WHERE license_key = ?", key,
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

func (b *SupportBot) handleRegister(msg *tgMessage) {
	// Check if this Telegram user already has an account
	var existingUser string
	err := db.QueryRow(b.db, "SELECT u.username FROM users u JOIN recovery_codes rc ON rc.user_id = u.id WHERE rc.code_hash = ? LIMIT 1", fmt.Sprintf("%d", msg.From.ID)).Scan(&existingUser)
	if err == nil {
		b.send(msg.Chat.ID, "You already have an account: "+existingUser+"\nUse /help for available commands.")
		return
	}

	// Generate credentials
	username := "user_" + randomString(8)
	password := randomString(16)

	// Create user
	userID := uuid.New().String()
	passwordHash, err := hashPassword(password)
	if err != nil {
		slog.Error("failed to hash password", "err", err)
		b.send(msg.Chat.ID, "Something went wrong. Please try again later.")
		return
	}

	_, err = db.Exec(b.db,
		"INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, 'worker')",
		userID, username, passwordHash,
	)
	if err != nil {
		slog.Error("failed to create user", "err", err)
		b.send(msg.Chat.ID, "Something went wrong. Please try again later.")
		return
	}

	// Generate 8 recovery codes
	codes := make([]string, 8)
	for i := range codes {
		code := randomString(10)
		codes[i] = code

		codeHash := sha256.Sum256([]byte(code))
		codeID := uuid.New().String()
		db.Exec(b.db,
			"INSERT INTO recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)",
			codeID, userID, hex.EncodeToString(codeHash[:]),
		)
	}

	// Send credentials to user
	text := fmt.Sprintf(
		"✅ **Account Created**\n\n"+
			"**Username:** `%s`\n"+
			"**Password:** `%s`\n\n"+
			"**Recovery Codes** (save these securely, each can be used once):\n",
		username, password,
	)
	for i, code := range codes {
		text += fmt.Sprintf("%d. `%s`\n", i+1, code)
	}
	text += "\n⚠️ These codes are the ONLY way to recover your password. Save them now!"

	b.send(msg.Chat.ID, text)
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	const charset = "abcdefghijkmnpqrstuvwxyz23456789"
	for i, v := range b {
		b[i] = charset[int(v)%len(charset)]
	}
	return string(b)
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", err
	}
	return string(hash), nil
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
