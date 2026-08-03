package api

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
)

type ReferralHandler struct {
	db       *sql.DB
	provider db.ProviderType
}

func NewReferralHandler(dbConn *sql.DB, provider db.ProviderType) *ReferralHandler {
	return &ReferralHandler{db: dbConn, provider: provider}
}

func generateReferralCode() string {
	b := make([]byte, 6)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (h *ReferralHandler) GetCode(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	code, err := h.ensureCode(claims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get referral code")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"code": code})
}

func (h *ReferralHandler) Apply(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Code == "" {
		writeError(w, http.StatusBadRequest, "code is required")
		return
	}

	var referrerID string
	err := h.db.QueryRow("SELECT id FROM users WHERE referral_code = ?", req.Code).Scan(&referrerID)
	if err != nil {
		writeError(w, http.StatusNotFound, "invalid referral code")
		return
	}

	if referrerID == claims.UserID {
		writeError(w, http.StatusBadRequest, "cannot refer yourself")
		return
	}

	var refCount int
	h.db.QueryRow("SELECT COUNT(*) FROM referrals WHERE referred_user_id = ?", claims.UserID).Scan(&refCount)
	if refCount > 0 {
		writeError(w, http.StatusBadRequest, "already applied a referral code")
		return
	}
	insertReferral := db.Placeholders(h.provider,
		"INSERT INTO referrals (referrer_id, referred_user_id, code, applied_at) VALUES (?, ?, ?, "+db.Now(h.provider)+")")
	_, err = h.db.Exec(insertReferral, referrerID, claims.UserID, req.Code)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to apply referral code")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "referral code applied",
		"code":    req.Code,
	})
}

func (h *ReferralHandler) Stats(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	code, err := h.ensureCode(claims)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to get referral code")
		return
	}

	var totalRefers int
	h.db.QueryRow("SELECT COUNT(*) FROM purchases WHERE referred_by = ?", claims.UserID).Scan(&totalRefers)

	writeJSON(w, http.StatusOK, map[string]any{
		"code":         code,
		"total_refers": totalRefers,
	})
}

func (h *ReferralHandler) ensureCode(claims *auth.Claims) (string, error) {
	var code string
	err := h.db.QueryRow("SELECT referral_code FROM users WHERE id = ?", claims.UserID).Scan(&code)
	if err != nil || code == "" {
		code = generateReferralCode()
		_, err = h.db.Exec("UPDATE users SET referral_code = ? WHERE id = ?", code, claims.UserID)
		if err != nil {
			return "", err
		}
	}
	return code, nil
}
