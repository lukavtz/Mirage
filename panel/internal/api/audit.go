package api

import (
	"database/sql"
	"log/slog"
	"net/http"
	"strconv"

	"zialfi-panel/internal/db"
)

func LogAudit(d *sql.DB, userID, action, details, ip string) {
	_, err := db.Exec(d, "INSERT INTO audit_log (user_id, action, details, ip) VALUES (?, ?, ?, ?)",
		userID, action, details, ip)
	if err != nil {
		slog.Error("failed to write audit log", "action", action, "err", err)
	}
}

type AuditHandler struct {
	db *sql.DB
}

func NewAuditHandler(db *sql.DB) *AuditHandler {
	return &AuditHandler{db: db}
}

type auditEntry struct {
	ID           string  `json:"id"`
	UserID       string  `json:"user_id"`
	Action       string  `json:"action"`
	Details      string  `json:"details"`
	IP           string  `json:"ip"`
	TargetUserID *string `json:"target_user_id"`
	CreatedAt    string  `json:"created_at"`
}

func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 50
	}

	query := "SELECT id, user_id, action, details, ip, target_user_id, created_at FROM audit_log"
	args := []any{}

	workerID := r.URL.Query().Get("worker_id")
	actionFilter := r.URL.Query().Get("action")
	var conditions []string
	if workerID != "" {
		conditions = append(conditions, "user_id = ?")
		args = append(args, workerID)
	}
	if actionFilter != "" {
		conditions = append(conditions, "action = ?")
		args = append(args, actionFilter)
	}
	if len(conditions) > 0 {
		query += " WHERE " + joinConditions(conditions)
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM audit_log"
	if len(conditions) > 0 {
		countQuery += " WHERE " + joinConditions(conditions)
	}
	db.QueryRow(h.db, countQuery, args...).Scan(&total)

	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	offset := (page - 1) * limit
	qargs := append(args, limit, offset)

	rows, err := db.Query(h.db, query, qargs...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to query audit log")
		return
	}
	defer rows.Close()

	entries := make([]auditEntry, 0)
	for rows.Next() {
		var e auditEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.Action, &e.Details, &e.IP, &e.TargetUserID, &e.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan audit entry")
			return
		}
		entries = append(entries, e)
	}

	pages := (total + limit - 1) / limit
	writeJSON(w, http.StatusOK, map[string]any{
		"items": entries,
		"total": total,
		"page":  page,
		"pages": pages,
	})
}

type auditStats struct {
	SessionsViewed int `json:"sessions_viewed"`
	Exports        int `json:"exports"`
	Locks          int `json:"locks"`
	Comments       int `json:"comments"`
	Total          int `json:"total"`
}

func (h *AuditHandler) Stats(w http.ResponseWriter, r *http.Request) {
	claims := claimsFromCtx(r)
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	workerID := r.URL.Query().Get("worker_id")
	if workerID == "" {
		workerID = claims.UserID
	}
	if claims.Role != "admin" && workerID != claims.UserID {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	today := "date_trunc('day', CURRENT_TIMESTAMP)"
	var stats auditStats

	db.QueryRow(h.db, "SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND action LIKE 'session.view%' AND created_at >= "+today, workerID).Scan(&stats.SessionsViewed)
	db.QueryRow(h.db, "SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND action = 'session.export' AND created_at >= "+today, workerID).Scan(&stats.Exports)
	db.QueryRow(h.db, "SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND action IN ('session.lock','session.unlock') AND created_at >= "+today, workerID).Scan(&stats.Locks)
	db.QueryRow(h.db, "SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND action = 'session.comment' AND created_at >= "+today, workerID).Scan(&stats.Comments)
	db.QueryRow(h.db, "SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND created_at >= "+today, workerID).Scan(&stats.Total)

	writeJSON(w, http.StatusOK, stats)
}

func joinConditions(conds []string) string {
	if len(conds) == 0 {
		return "1=1"
	}
	result := conds[0]
	for _, c := range conds[1:] {
		result += " AND " + c
	}
	return result
}

func LogWorkerAction(d *sql.DB, userID, action, details, ip string, targetUserID *string) {
	_, err := db.Exec(d, "INSERT INTO audit_log (user_id, action, details, ip, target_user_id) VALUES (?, ?, ?, ?, ?)",
		userID, action, details, ip, targetUserID)
	if err != nil {
		slog.Error("failed to write audit log", "action", action, "err", err)
	}
}
