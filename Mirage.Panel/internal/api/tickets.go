package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/user/mirage-panel/internal/middleware"
)

type TicketHandler struct {
	db *sql.DB
}

func NewTicketHandler(db *sql.DB) *TicketHandler {
	return &TicketHandler{db: db}
}

type Ticket struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	Subject   string `json:"subject"`
	Category  string `json:"category"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type TicketReply struct {
	ID        string `json:"id"`
	TicketID  string `json:"ticket_id"`
	UserID    string `json:"user_id"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

type TicketDetail struct {
	Ticket
	Replies []TicketReply `json:"replies"`
}

var validCategories = map[string]bool{
	"bug":      true,
	"feature":  true,
	"question": true,
	"other":    true,
}

func (h *TicketHandler) Create(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Subject  string `json:"subject"`
		Category string `json:"category"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Subject == "" {
		writeError(w, http.StatusBadRequest, "subject is required")
		return
	}
	if !validCategories[req.Category] {
		writeError(w, http.StatusBadRequest, "invalid category, must be one of: bug, feature, question, other")
		return
	}

	id := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := h.db.Exec(
		"INSERT INTO support_tickets (id, user_id, subject, category, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, claims.UserID, req.Subject, req.Category, now, now,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create ticket")
		return
	}

	var t Ticket
	err = h.db.QueryRow(
		"SELECT id, user_id, subject, category, status, created_at, updated_at FROM support_tickets WHERE id = ?", id,
	).Scan(&t.ID, &t.UserID, &t.Subject, &t.Category, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read back ticket")
		return
	}

	writeJSON(w, http.StatusCreated, t)
}

func (h *TicketHandler) List(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var rows *sql.Rows
	var err error

	if claims.Role == "admin" {
		rows, err = h.db.Query("SELECT id, user_id, subject, category, status, created_at, updated_at FROM support_tickets ORDER BY updated_at DESC")
	} else {
		rows, err = h.db.Query("SELECT id, user_id, subject, category, status, created_at, updated_at FROM support_tickets WHERE user_id = ? ORDER BY updated_at DESC", claims.UserID)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query tickets")
		return
	}
	defer rows.Close()

	tickets := make([]Ticket, 0)
	for rows.Next() {
		var t Ticket
		if err := rows.Scan(&t.ID, &t.UserID, &t.Subject, &t.Category, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
			continue
		}
		tickets = append(tickets, t)
	}

	writeJSON(w, http.StatusOK, tickets)
}

func (h *TicketHandler) Get(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := chi.URLParam(r, "id")

	var t TicketDetail
	err := h.db.QueryRow(
		"SELECT id, user_id, subject, category, status, created_at, updated_at FROM support_tickets WHERE id = ?", id,
	).Scan(&t.ID, &t.UserID, &t.Subject, &t.Category, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}

	if claims.Role != "admin" && t.UserID != claims.UserID {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	replyRows, err := h.db.Query(
		"SELECT id, ticket_id, user_id, message, created_at FROM ticket_replies WHERE ticket_id = ? ORDER BY created_at ASC", id,
	)
	if err == nil {
		defer replyRows.Close()
		t.Replies = make([]TicketReply, 0)
		for replyRows.Next() {
			var rpl TicketReply
			if err := replyRows.Scan(&rpl.ID, &rpl.TicketID, &rpl.UserID, &rpl.Message, &rpl.CreatedAt); err != nil {
				continue
			}
			t.Replies = append(t.Replies, rpl)
		}
	}

	writeJSON(w, http.StatusOK, t)
}

func (h *TicketHandler) Reply(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := chi.URLParam(r, "id")

	var t Ticket
	err := h.db.QueryRow(
		"SELECT id, user_id, subject, category, status, created_at, updated_at FROM support_tickets WHERE id = ?", id,
	).Scan(&t.ID, &t.UserID, &t.Subject, &t.Category, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}

	if claims.Role != "admin" && t.UserID != claims.UserID {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	var req struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Message == "" {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}

	replyID := uuid.New().String()
	now := time.Now().UTC().Format(time.RFC3339)

	_, err = h.db.Exec(
		"INSERT INTO ticket_replies (id, ticket_id, user_id, message, created_at) VALUES (?, ?, ?, ?, ?)",
		replyID, id, claims.UserID, req.Message, now,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to save reply")
		return
	}

	_, err = h.db.Exec("UPDATE support_tickets SET status = 'open', updated_at = ? WHERE id = ?", now, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update ticket")
		return
	}

	var rpl TicketReply
	err = h.db.QueryRow(
		"SELECT id, ticket_id, user_id, message, created_at FROM ticket_replies WHERE id = ?", replyID,
	).Scan(&rpl.ID, &rpl.TicketID, &rpl.UserID, &rpl.Message, &rpl.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read back reply")
		return
	}

	writeJSON(w, http.StatusCreated, rpl)
}

func (h *TicketHandler) Close(w http.ResponseWriter, r *http.Request) {
	claims := middleware.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := chi.URLParam(r, "id")

	var t Ticket
	err := h.db.QueryRow(
		"SELECT id, user_id, subject, category, status, created_at, updated_at FROM support_tickets WHERE id = ?", id,
	).Scan(&t.ID, &t.UserID, &t.Subject, &t.Category, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		writeError(w, http.StatusNotFound, "ticket not found")
		return
	}

	if claims.Role != "admin" && t.UserID != claims.UserID {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	if t.Status == "closed" {
		writeError(w, http.StatusBadRequest, "ticket is already closed")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = h.db.Exec("UPDATE support_tickets SET status = 'closed', updated_at = ? WHERE id = ?", now, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to close ticket")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "ticket closed"})
}
