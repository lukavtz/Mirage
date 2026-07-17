package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/user/mirage-panel/internal/auth"
	mw "github.com/user/mirage-panel/internal/middleware"
	"golang.org/x/crypto/bcrypt"
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
	db             *sql.DB
	jwtSecret      string
	rateLimiter    *ipRateLimiter
	failedAttempts map[string]int
	failedMu       sync.Mutex
	tempTokens     map[string]tempTokenEntry
	tempMu         sync.Mutex
}

func NewAuthHandler(db *sql.DB, jwtSecret string) *AuthHandler {
	h := &AuthHandler{
		db:             db,
		jwtSecret:      jwtSecret,
		rateLimiter:    newIPRateLimiter(),
		failedAttempts: make(map[string]int),
		tempTokens:     make(map[string]tempTokenEntry),
	}
	go h.cleanupFailedAttempts()
	go h.cleanupTempTokens()
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

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r)

	var banID string
	err := h.db.QueryRow("SELECT id FROM bans WHERE ip = ?", ip).Scan(&banID)
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
	err = h.db.QueryRow(
		"SELECT id, username, password_hash, role FROM users WHERE username = ?",
		req.Username,
	).Scan(&id, &username, &passwordHash, &role)
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
	h.db.QueryRow("SELECT totp_enabled, totp_secret FROM users WHERE id = ?", id).Scan(&totpEnabled, &totpSecret)
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
	token, expiresAt, err := auth.GenerateTokenWithSession(id, role, sessionID, h.jwtSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	ua := r.Header.Get("User-Agent")
	os, browser := parseUserAgent(ua)
	h.db.Exec(`INSERT INTO auth_sessions (id, user_id, token_hash, device, os, browser, ip)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, sessionID, id, hashToken(token), "", os, browser, ip)

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
	err := h.db.QueryRow("SELECT totp_secret FROM users WHERE id = ?", entry.userID).Scan(&secret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if !auth.NewTOTPManager().Validate(req.Passcode, secret) {
		writeError(w, http.StatusUnauthorized, "invalid passcode")
		return
	}

	ip := extractIP(r)
	sessionID := uuid.New().String()
	token, expiresAt, err := auth.GenerateTokenWithSession(entry.userID, entry.role, sessionID, h.jwtSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	ua := r.Header.Get("User-Agent")
	os, browser := parseUserAgent(ua)
	h.db.Exec(`INSERT INTO auth_sessions (id, user_id, token_hash, device, os, browser, ip)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, sessionID, entry.userID, hashToken(token), "", os, browser, ip)

	score := mw.CheckIP(ip)

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339),
		"ip_score":   score.Score,
		"ip_threat":  score.Threat,
	})
}

func (h *AuthHandler) recordFailedAttempt(ip string) {
	h.failedMu.Lock()
	defer h.failedMu.Unlock()

	h.failedAttempts[ip]++
	if h.failedAttempts[ip] > 10 {
		id := uuid.New().String()
		h.db.Exec("INSERT INTO bans (id, ip, reason) VALUES (?, ?, ?)",
			id, ip, "auto-ban: too many failed login attempts")
		delete(h.failedAttempts, ip)
	}
}
