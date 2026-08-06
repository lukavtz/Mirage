package api

import (
	"database/sql"
	"log/slog"
	"net/http"
	"strconv"

	"zialfi-panel/internal/db"
)

// logActivity records a worker action in the worker_activity table.
func logActivity(d *sql.DB, userID, action, targetID string) {
	var tid any
	if targetID != "" {
		tid = targetID
	}
	_, err := db.Exec(d,
		"INSERT INTO worker_activity (user_id, action, target_id) VALUES (?, ?, ?)",
		userID, action, tid)
	if err != nil {
		slog.Error("failed to log worker activity", "action", action, "err", err)
	}
}

type WorkerActivityHandler struct {
	db *sql.DB
}

func NewWorkerActivityHandler(d *sql.DB) *WorkerActivityHandler {
	return &WorkerActivityHandler{db: d}
}

type activityEntry struct {
	ID        string  `json:"id"`
	UserID    string  `json:"user_id"`
	Action    string  `json:"action"`
	TargetID  *string `json:"target_id"`
	CreatedAt string  `json:"created_at"`
}

// List returns paginated worker activity. Admin-only.
func (h *WorkerActivityHandler) List(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 50
	}

	var conditions []string
	var args []any

	if userID := r.URL.Query().Get("user_id"); userID != "" {
		conditions = append(conditions, "user_id = ?")
		args = append(args, userID)
	}
	if action := r.URL.Query().Get("action"); action != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, action)
	}

	where := ""
	if len(conditions) > 0 {
		where = " WHERE "
		for i, c := range conditions {
			if i > 0 {
				where += " AND "
			}
			where += c
		}
	}

	var total int
	countQ := "SELECT COUNT(*) FROM worker_activity" + where
	db.QueryRow(h.db, countQ, args...).Scan(&total)

	offset := (page - 1) * limit
	query := "SELECT id, user_id, action, target_id, created_at FROM worker_activity" + where + " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	qargs := append(args, limit, offset)

	rows, err := db.Query(h.db, query, qargs...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query activity")
		return
	}
	defer rows.Close()

	items := make([]activityEntry, 0)
	for rows.Next() {
		var e activityEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.TargetID, &e.CreatedAt); err != nil {
			continue
		}
		items = append(items, e)
	}

	pages := (total + limit - 1) / limit
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": total,
		"page":  page,
		"pages": pages,
	})
}
