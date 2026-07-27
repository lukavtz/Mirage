package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type NotesHandler struct {
	db *sql.DB
}

func NewNotesHandler(db *sql.DB) *NotesHandler {
	return &NotesHandler{db: db}
}

type Note struct {
	ID        string `json:"id"`
	SessionID string `json:"session_id"`
	Content   string `json:"content"`
	CreatedBy string `json:"created_by"`
	CreatedAt string `json:"created_at"`
}

func (h *NotesHandler) List(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")

	rows, err := h.db.Query(
		"SELECT id, session_id, content, created_by, created_at FROM notes WHERE session_id = ? ORDER BY created_at DESC",
		sessionID,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query notes")
		return
	}
	defer rows.Close()

	notes := make([]Note, 0)
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.SessionID, &n.Content, &n.CreatedBy, &n.CreatedAt); err != nil {
			continue
		}
		notes = append(notes, n)
	}

	writeJSON(w, http.StatusOK, notes)
}

func (h *NotesHandler) Create(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "id")

	var req struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.Content == "" {
		writeError(w, http.StatusBadRequest, "content is required")
		return
	}

	id := uuid.New().String()
	_, err := h.db.Exec(
		"INSERT INTO notes (id, session_id, content) VALUES (?, ?, ?)",
		id, sessionID, req.Content,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create note")
		return
	}

	var n Note
	err = h.db.QueryRow(
		"SELECT id, session_id, content, created_by, created_at FROM notes WHERE id = ?", id,
	).Scan(&n.ID, &n.SessionID, &n.Content, &n.CreatedBy, &n.CreatedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read back note")
		return
	}

	writeJSON(w, http.StatusCreated, n)
}

func (h *NotesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	result, err := h.db.Exec("DELETE FROM notes WHERE id = ?", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete note")
		return
	}

	rows, err := result.RowsAffected()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to check deletion result")
		return
	}

	if rows == 0 {
		writeError(w, http.StatusNotFound, "note not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "note deleted"})
}
