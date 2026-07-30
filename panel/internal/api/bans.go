package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

type BanHandler struct {
	db *sql.DB
}

func NewBanHandler(db *sql.DB) *BanHandler {
	return &BanHandler{db: db}
}

type banRecord struct {
	ID        string  `json:"id"`
	IP        string  `json:"ip"`
	HWID      *string `json:"hwid"`
	Reason    string  `json:"reason"`
	CreatedBy *string `json:"created_by"`
	BannedAt  string  `json:"banned_at"`
}

func (h *BanHandler) List(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query("SELECT id, ip, hwid, reason, created_by, banned_at FROM bans ORDER BY banned_at DESC")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query bans")
		return
	}
	defer rows.Close()

	bans := make([]banRecord, 0)
	for rows.Next() {
		var b banRecord
		if err := rows.Scan(&b.ID, &b.IP, &b.HWID, &b.Reason, &b.CreatedBy, &b.BannedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan ban")
			return
		}
		bans = append(bans, b)
	}

	writeJSON(w, http.StatusOK, bans)
}

func (h *BanHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP     string `json:"ip"`
		HWID   string `json:"hwid,omitempty"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.IP == "" && req.HWID == "" {
		writeError(w, http.StatusBadRequest, "ip or hwid required")
		return
	}
	if req.Reason == "" {
		req.Reason = "banned by admin"
	}

	claims, ok := getClaims(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	id := uuid.New().String()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")

	_, err := h.db.Exec(
		"INSERT INTO bans (id, ip, hwid, reason, created_by, banned_at) VALUES (?, ?, ?, ?, ?, ?)",
		id, req.IP, nullIfEmpty(req.HWID), req.Reason, claims.UserID, now,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create ban")
		return
	}

	LogAudit(h.db, claims.UserID, "ban.create", "Banned IP "+req.IP+" HWID "+req.HWID, extractIP(r))

	writeJSON(w, http.StatusCreated, banRecord{
		ID:        id,
		IP:        req.IP,
		Reason:    req.Reason,
		CreatedBy: &claims.UserID,
		BannedAt:  now,
	})
}

func (h *BanHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	result, err := h.db.Exec("DELETE FROM bans WHERE id = ?", id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to delete ban")
		return
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		writeError(w, http.StatusNotFound, "ban not found")
		return
	}

	claims, ok := getClaims(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	LogAudit(h.db, claims.UserID, "ban.delete", "Removed ban "+id, extractIP(r))

	writeJSON(w, http.StatusOK, map[string]string{"message": "ban removed"})
}
