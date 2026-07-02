package api

import (
	"database/sql"
	"log/slog"
)

func LogAudit(db *sql.DB, userID, action, details, ip string) {
	_, err := db.Exec(
		"INSERT INTO audit_log (user_id, action, details, ip) VALUES (?, ?, ?, ?)",
		userID, action, details, ip,
	)
	if err != nil {
		slog.Error("failed to write audit log", "action", action, "err", err)
	}
}
