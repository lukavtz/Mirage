package api

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	mw "zialfi-panel/internal/middleware"
)

type ipRateLimiter struct {
	mu     sync.Mutex
	limits map[string]*ipRateEntry
}

type ipRateEntry struct {
	count int
	start time.Time
}

func newIPRateLimiter() *ipRateLimiter {
	return &ipRateLimiter{limits: make(map[string]*ipRateEntry)}
}

func (rl *ipRateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	entry, ok := rl.limits[ip]
	if !ok || now.Sub(entry.start) > time.Minute {
		rl.limits[ip] = &ipRateEntry{count: 1, start: now}
		return true
	}

	entry.count++
	return entry.count <= 5
}

type tempTokenEntry struct {
	userID    string
	role      string
	expiresAt time.Time
}
type AuthHandler struct {
	db              *sql.DB
	jwtSecret       string
	rateLimiter     *ipRateLimiter
	forgotPwLimiter *ipRateLimiter
	failedAttempts  map[string]int
	failedMu        sync.Mutex
	tempTokens      map[string]tempTokenEntry
	tempMu          sync.Mutex
}

func NewAuthHandler(dbConn *sql.DB, jwtSecret string) *AuthHandler {
	h := &AuthHandler{
		db:              dbConn,
		jwtSecret:       jwtSecret,
		rateLimiter:     newIPRateLimiter(),
		forgotPwLimiter: newIPRateLimiter(),
		failedAttempts:  make(map[string]int),
		tempTokens:      make(map[string]tempTokenEntry),
	}
	go h.cleanupFailedAttempts()
	go h.cleanupTempTokens()
	go h.cleanupPasswordResets()
	return h
}

func (h *AuthHandler) cleanupTempTokens() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		h.tempMu.Lock()
		now := time.Now()
		for token, entry := range h.tempTokens {
			if now.After(entry.expiresAt) {
				delete(h.tempTokens, token)
			}
		}
		h.tempMu.Unlock()
	}
}

func (h *AuthHandler) cleanupFailedAttempts() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		h.failedMu.Lock()
		h.failedAttempts = make(map[string]int)
		h.failedMu.Unlock()
	}
}

func (h *AuthHandler) cleanupPasswordResets() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		db.Exec(h.db, db.Placeholders("DELETE FROM password_resets WHERE expires_at < "+db.Now()+" OR used = 1"))
	}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r)

	var banID string
	err := db.QueryRow(h.db, "SELECT id FROM bans WHERE ip = ?", ip).Scan(&banID)
	if err == nil {
		writeError(w, http.StatusForbidden, "IP is banned")
		return
	}
	if err != sql.ErrNoRows {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if !h.rateLimiter.Allow(ip) {
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "username and password are required")
		return
	}

	var id, username, passwordHash, role string
	err = db.QueryRow(h.db, "SELECT id, username, password_hash, role FROM users WHERE username = ?",
		req.Username).Scan(&id, &username, &passwordHash, &role)
	if err == sql.ErrNoRows {
		h.recordFailedAttempt(ip)
		// ponytail: consistent error message regardless of whether user
		// exists — prevents trivial username enumeration via response text.
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		h.recordFailedAttempt(ip)
		writeError(w, http.StatusUnauthorized, "invalid username or password")
		return
	}

	var totpEnabled bool
	var totpSecret string
	if err := db.QueryRow(h.db, "SELECT totp_enabled, totp_secret FROM users WHERE id = ?", id).Scan(&totpEnabled, &totpSecret); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if totpEnabled {
		tempToken := uuid.New().String()
		h.tempMu.Lock()
		h.tempTokens[tempToken] = tempTokenEntry{userID: id, role: role, expiresAt: time.Now().Add(5 * time.Minute)}
		h.tempMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"totp_required": true,
			"totp_token":    tempToken,
		})
		return
	}

	sessionID := uuid.New().String()
	var tv int
	if err := db.QueryRow(h.db, "SELECT COALESCE(token_version, 0) FROM users WHERE id = ?", id).Scan(&tv); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	token, expiresAt, err := auth.GenerateTokenWithSession(id, role, sessionID, h.jwtSecret, tv)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	ua := r.Header.Get("User-Agent")
	os, browser := ParseUserAgent(ua)
	if _, err := db.Exec(h.db, `INSERT INTO auth_sessions (id, user_id, token_hash, device, os, browser, ip)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, sessionID, id, hashToken(token), "", os, browser, ip); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	score := mw.CheckIP(ip)

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339),
		"ip_score":   score.Score,
		"ip_threat":  score.Threat,
	})
}

func (h *AuthHandler) VerifyLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TotpToken string `json:"totp_token"`
		Passcode  string `json:"passcode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	h.tempMu.Lock()
	entry, ok := h.tempTokens[req.TotpToken]
	if ok {
		delete(h.tempTokens, req.TotpToken)
	}
	h.tempMu.Unlock()
	if !ok || time.Now().After(entry.expiresAt) {
		writeError(w, http.StatusUnauthorized, "invalid or expired TOTP token")
		return
	}

	var secret string
	if err := db.QueryRow(h.db, "SELECT totp_secret FROM users WHERE id = ?", entry.userID).Scan(&secret); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !auth.NewTOTPManager().Validate(req.Passcode, secret) {
		writeError(w, http.StatusUnauthorized, "invalid passcode")
		return
	}

	ip := extractIP(r)
	var tv int
	if err := db.QueryRow(h.db, "SELECT COALESCE(token_version, 0) FROM users WHERE id = ?", entry.userID).Scan(&tv); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	sessionID := uuid.New().String()
	token, expiresAt, err := auth.GenerateTokenWithSession(entry.userID, entry.role, sessionID, h.jwtSecret, tv)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ua := r.Header.Get("User-Agent")
	os, browser := ParseUserAgent(ua)
	if _, err := db.Exec(h.db, `INSERT INTO auth_sessions (id, user_id, token_hash, device, os, browser, ip)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, sessionID, entry.userID, hashToken(token), "", os, browser, ip); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	score := mw.CheckIP(ip)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339),
		"ip_score":   score.Score,
		"ip_threat":  score.Threat,
	})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims, _ := getClaims(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	var totpEnabled bool
	db.QueryRow(h.db, "SELECT totp_enabled FROM users WHERE id = ?", claims.UserID).Scan(&totpEnabled)
	writeJSON(w, http.StatusOK, map[string]any{
		"user_id":      claims.UserID,
		"role":         claims.Role,
		"totp_enabled": totpEnabled,
	})
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r)

	if !h.forgotPwLimiter.Allow(ip) {
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	const genericMsg = "If the account exists, a reset token has been generated."

	var userID string
	err := db.QueryRow(h.db, "SELECT id FROM users WHERE username = ?", req.Username).Scan(&userID)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"message": genericMsg})
		return
	}

	// Generate random 32-byte token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	token := hex.EncodeToString(tokenBytes)

	// Hash with SHA256 for storage
	hash := sha256.Sum256(tokenBytes)
	tokenHash := hex.EncodeToString(hash[:])

	id := uuid.New().String()
	expiresAt := time.Now().Add(15 * time.Minute)
	_, err = db.Exec(h.db, "INSERT INTO password_resets (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)",
		id, userID, tokenHash, expiresAt.UTC().Format(time.RFC3339))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Send token via Telegram if configured, otherwise log to console
	var tgToken, tgChatID string
	db.QueryRow(h.db, "SELECT value FROM settings WHERE key = 'telegram_token'").Scan(&tgToken)
	db.QueryRow(h.db, "SELECT value FROM settings WHERE key = 'telegram_chat_id'").Scan(&tgChatID)

	if tgToken != "" && tgChatID != "" {
		text := fmt.Sprintf("🔐 Password reset requested\n\nUser: %s\nCode: %s\nExpires: 15 minutes", req.Username, token)
		go func() {
			apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", tgToken)
			form := url.Values{}
			form.Set("chat_id", tgChatID)
			form.Set("text", text)
			http.PostForm(apiURL, form)
		}()
	} else {
		slog.Warn("password reset code (no Telegram configured)", "user", req.Username, "code", token)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"message": genericMsg,
	})
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	if len(req.NewPassword) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	// Hash the provided token to look up in DB
	tokenBytes, err := hex.DecodeString(req.Token)
	if err != nil || len(tokenBytes) != 32 {
		writeError(w, http.StatusBadRequest, "invalid token format")
		return
	}
	hash := sha256.Sum256(tokenBytes)
	tokenHash := hex.EncodeToString(hash[:])

	var resetID, userID string
	var expiresAt time.Time
	var used bool
	err = db.QueryRow(h.db, "SELECT id, user_id, expires_at, used FROM password_resets WHERE token_hash = ?",
		tokenHash).Scan(&resetID, &userID, &expiresAt, &used)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusBadRequest, "invalid or expired reset token")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if used {
		writeError(w, http.StatusBadRequest, "reset token already used")
		return
	}
	if err != nil || time.Now().After(expiresAt) {
		writeError(w, http.StatusBadRequest, "reset token has expired")
		return
	}

	// Hash new password with bcrypt (cost 12)
	passwordHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	tx, err := h.db.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	rollback := func() {
		_ = tx.Rollback()
	}
	if _, err = tx.Exec(db.Placeholders("UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?"), passwordHash, userID); err != nil {
		rollback()
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	result, err := tx.Exec("UPDATE password_resets SET used = TRUE WHERE id = $1 AND used = FALSE", resetID)
	if err != nil {
		rollback()
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		rollback()
		writeError(w, http.StatusBadRequest, "reset token already used")
		return
	}
	if _, err = tx.Exec("DELETE FROM auth_sessions WHERE user_id = $1", userID); err != nil {
		rollback()
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err = tx.Commit(); err != nil {
		rollback()
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "Password reset successfully"})
}

func (h *AuthHandler) recordFailedAttempt(ip string) {
	var shouldBan bool
	func() {
		h.failedMu.Lock()
		defer h.failedMu.Unlock()

		h.failedAttempts[ip]++
		if h.failedAttempts[ip] > 10 {
			shouldBan = true
			delete(h.failedAttempts, ip)
		}
	}()

	if shouldBan {
		id := uuid.New().String()
		_, _ = db.Exec(h.db, "INSERT INTO bans (id, ip, reason) VALUES (?, ?, ?)",
			id, ip, "auto-ban: too many failed login attempts")
	}
}
