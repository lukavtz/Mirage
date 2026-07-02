package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/user/mirage-panel/internal/auth"
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

type AuthHandler struct {
	db             *sql.DB
	jwtSecret      string
	rateLimiter    *ipRateLimiter
	failedAttempts map[string]int
	failedMu       sync.Mutex
}

func NewAuthHandler(db *sql.DB, jwtSecret string) *AuthHandler {
	return &AuthHandler{
		db:             db,
		jwtSecret:      jwtSecret,
		rateLimiter:    newIPRateLimiter(),
		failedAttempts: make(map[string]int),
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

	var id, username, passwordHash, role, createdAt string
	err = h.db.QueryRow(
		"SELECT id, username, password_hash, role, created_at FROM users WHERE username = ?",
		req.Username,
	).Scan(&id, &username, &passwordHash, &role, &createdAt)
	if err == sql.ErrNoRows {
		h.recordFailedAttempt(ip)
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

	token, expiresAt, err := auth.GenerateToken(id, role, h.jwtSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      token,
		"expires_at": expiresAt.Format(time.RFC3339),
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
