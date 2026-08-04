package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
)

type TOTPHandler struct {
	db          *sql.DB
	provider     db.ProviderType
	totpManager *auth.TOTPManager
}

func NewTOTPHandler(db *sql.DB, provider db.ProviderType) *TOTPHandler {
	return &TOTPHandler{db: db, totpManager: auth.NewTOTPManager()}
}

func (h *TOTPHandler) Setup(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	secret, qrBase64, err := h.totpManager.GenerateSecret(claims.UserID, "Mirage")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate TOTP secret")
		return
	}

	_, err = db.Exec(h.db, h.provider, "UPDATE users SET totp_secret = ? WHERE id = ?", secret, claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save TOTP secret")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"qr_base64": qrBase64,
	})
}

func (h *TOTPHandler) Verify(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Passcode string `json:"passcode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	var secret string
	err := db.QueryRow(h.db, h.provider, "SELECT totp_secret FROM users WHERE id = ?", claims.UserID).Scan(&secret)
	if err != nil || secret == "" {
		writeError(w, http.StatusBadRequest, "TOTP not set up. Call setup first.")
		return
	}

	if !h.totpManager.Validate(req.Passcode, secret) {
		writeError(w, http.StatusBadRequest, "invalid passcode")
		return
	}

	_, err = db.Exec(h.db, h.provider, "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?", secret, claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to enable TOTP")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "2FA enabled"})
}

func (h *TOTPHandler) Disable(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	var passwordHash string
	err := db.QueryRow(h.db, h.provider, "SELECT password_hash FROM users WHERE id = ?", claims.UserID).Scan(&passwordHash)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch user")
		return
	}

	if !auth.CheckPassword(req.Password, passwordHash) {
		writeError(w, http.StatusBadRequest, "invalid password")
		return
	}

	_, err = db.Exec(h.db, h.provider, "UPDATE users SET totp_enabled = 0, totp_secret = '' WHERE id = ?", claims.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to disable TOTP")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "2FA disabled"})
}

func (h *TOTPHandler) Required(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		writeError(w, http.StatusBadRequest, "username is required")
		return
	}

	// Rate-limited but public — the response is the same shape regardless
	// of whether the user exists, preventing username enumeration. The
	// frontend should prefer the login response's totp_required field.
	var enabled bool
	_ = db.QueryRow(h.db, h.provider, "SELECT totp_enabled FROM users WHERE username = ?", username).Scan(&enabled)

	writeJSON(w, http.StatusOK, map[string]bool{"required": enabled})
}
