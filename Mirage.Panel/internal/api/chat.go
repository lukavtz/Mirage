package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/user/mirage-panel/internal/middleware"
	"github.com/user/mirage-panel/internal/ws"
)

type ChatHandler struct {
	db  *sql.DB
	hub *ws.Hub
}

func NewChatHandler(db *sql.DB, hub *ws.Hub) *ChatHandler {
	return &ChatHandler{db: db, hub: hub}
}

func (h *ChatHandler) List(w http.ResponseWriter, r *http.Request) {
	since := r.URL.Query().Get("since")
	if since == "" {
		since = "1970-01-01T00:00:00Z"
	}

	t, err := time.Parse(time.RFC3339, since)
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05", since)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid since format, use RFC3339")
			return
		}
	}
	sinceFormatted := t.Format("2006-01-02 15:04:05")

	limit := r.URL.Query().Get("limit")
	if limit == "" {
		limit = "50"
	}

	rows, err := h.db.Query(
		"SELECT id, user_id, username, message, COALESCE(parent_id,''), message_type, created_at FROM chat_messages WHERE created_at > ? ORDER BY created_at DESC LIMIT ?",
		sinceFormatted, limit,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query messages")
		return
	}
	defer rows.Close()

	messages := make([]ws.ChatMessage, 0)
	for rows.Next() {
		var m ws.ChatMessage
		if err := rows.Scan(&m.ID, &m.UserID, &m.Username, &m.Message, &m.ParentID, &m.MessageType, &m.CreatedAt); err != nil {
			continue
		}
		messages = append(messages, m)
	}

	writeJSON(w, http.StatusOK, messages)
}

func (h *ChatHandler) Send(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Message  string `json:"message"`
		ParentID string `json:"parent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}

	var username string
	err := h.db.QueryRow("SELECT username FROM users WHERE id = ?", claims.UserID).Scan(&username)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to lookup user")
		return
	}

	id := uuid.New().String()
	_, err = h.db.Exec(
		"INSERT INTO chat_messages (id, user_id, username, message, parent_id) VALUES (?, ?, ?, ?, ?)",
		id, claims.UserID, username, req.Message, nullIfEmpty(req.ParentID),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save message")
		return
	}

	var m ws.ChatMessage
	err = h.db.QueryRow(
		"SELECT id, user_id, username, message, COALESCE(parent_id,''), message_type, created_at FROM chat_messages WHERE id = ?", id,
	).Scan(&m.ID, &m.UserID, &m.Username, &m.Message, &m.ParentID, &m.MessageType, &m.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read back message")
		return
	}

	h.hub.BroadcastChat(m)

	writeJSON(w, http.StatusCreated, m)
}

func (h *ChatHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	result, err := h.db.Exec("DELETE FROM chat_messages WHERE id = ?", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete message")
		return
	}

	rows, err := result.RowsAffected()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check result")
		return
	}
	if rows == 0 {
		writeError(w, http.StatusNotFound, "message not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "message deleted"})
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
