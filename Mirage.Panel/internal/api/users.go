package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/user/mirage-panel/internal/auth"
)

type UsersHandler struct {
	db        *sql.DB
	jwtSecret string
}

func NewUsersHandler(db *sql.DB, jwtSecret string) *UsersHandler {
	return &UsersHandler{db: db, jwtSecret: jwtSecret}
}

type userListItem struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT id, username, role, created_at FROM users ORDER BY created_at DESC")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query users")
		return
	}
	defer rows.Close()

	users := make([]userListItem, 0)
	for rows.Next() {
		var u userListItem
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan user row")
			return
		}
		users = append(users, u)
	}

	writeJSON(w, http.StatusOK, users)
}

func generateInviteCode() string {
	b := make([]byte, 12)
	rand.Read(b)
	encoded := hex.EncodeToString(b)
	parts := []string{
		encoded[0:5],
		encoded[5:10],
		encoded[10:15],
		encoded[15:20],
		encoded[20:24],
	}
	return "MIRAGE-" + strings.Join(parts, "-")
}

func (h *UsersHandler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Role     string `json:"role"`
		Tier     string `json:"tier"`
		MaxUses  int    `json:"max_uses"`
		Duration string `json:"duration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Role == "" {
		req.Role = "worker"
	}
	if req.Tier == "" {
		req.Tier = "starter"
	}
	if req.MaxUses < 1 {
		req.MaxUses = 1
	}

	code := generateInviteCode()

	var expiresAt *string
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err == nil {
			exp := time.Now().Add(d).Format("2006-01-02 15:04:05")
			expiresAt = &exp
		}
	}

	claims, ok := getClaims(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	_, err := h.db.Exec(
		`INSERT INTO invite_codes (code, role, tier, max_uses, created_by, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		code, req.Role, req.Tier, req.MaxUses, claims.UserID, expiresAt,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create invite code")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"code":       code,
		"role":       req.Role,
		"tier":       req.Tier,
		"max_uses":   req.MaxUses,
		"expires_at": expiresAt,
	})
}

func (h *UsersHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username   string `json:"username"`
		Password   string `json:"password"`
		InviteCode string `json:"invite_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	if req.Username == "" || req.Password == "" || req.InviteCode == "" {
		writeError(w, http.StatusBadRequest, "username, password, and invite_code are required")
		return
	}

	var inviteID, role, tier, expiresAt sql.NullString
	var maxUses, usedCount int
	err := h.db.QueryRow(
		`SELECT id, role, tier, max_uses, used_count, expires_at
		 FROM invite_codes WHERE code = ?`, req.InviteCode,
	).Scan(&inviteID, &role, &tier, &maxUses, &usedCount, &expiresAt)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "invalid invite code")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to validate invite code")
		return
	}

	if expiresAt.Valid {
		expTime, err := time.ParseInLocation("2006-01-02 15:04:05", expiresAt.String, time.Local)
		if err == nil && time.Now().After(expTime) {
			writeError(w, http.StatusGone, "invite code has expired")
			return
		}
	}

	if usedCount >= maxUses {
		writeError(w, http.StatusConflict, "invite code has been used up")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	userID := uuid.New().String()
	tx, err := h.db.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()

	_, err = tx.Exec(
		"INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
		userID, req.Username, hash, role.String,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			writeError(w, http.StatusConflict, "username already taken")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	_, err = tx.Exec(
		"UPDATE invite_codes SET used_count = used_count + 1 WHERE id = ?",
		inviteID.String,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update invite code")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to complete registration")
		return
	}

	token, expiresAtTime, err := auth.GenerateToken(userID, role.String, h.jwtSecret)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         userID,
		"username":   req.Username,
		"role":       role.String,
		"tier":       tier.String,
		"token":      token,
		"expires_at": expiresAtTime.Format(time.RFC3339),
	})
}
