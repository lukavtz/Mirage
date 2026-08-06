package api

import (
	"database/sql"
	"net/http"

	"zialfi-panel/internal/middleware"

	"zialfi-panel/internal/db"
)

type DuplicateDetectHandler struct {
	db *sql.DB
}

func NewDuplicateDetectHandler(db *sql.DB) *DuplicateDetectHandler {
	return &DuplicateDetectHandler{db: db}
}

type DuplicateInfo struct {
	Count    int      `json:"count"`
	Sessions []string `json:"sessions"`
}

type DuplicateResponse struct {
	Hwid DuplicateInfo `json:"hwid"`
	Ip   DuplicateInfo `json:"ip"`
}

func (h *DuplicateDetectHandler) Detect(w http.ResponseWriter, r *http.Request) {
	hwid := r.URL.Query().Get("hwid")
	ip := r.URL.Query().Get("ip")

	if hwid == "" && ip == "" {
		writeError(w, http.StatusBadRequest, "hwid or ip required")
		return
	}

	resp := DuplicateResponse{}

	ownerClause := ""
	var ownerArg any
	if claims := middleware.ClaimsFromContext(r.Context()); claims != nil && claims.Role != "admin" {
		ownerClause = " AND owner_id = ?"
		ownerArg = claims.UserID
	}

	if hwid != "" {
		var count int
		args := []any{hwid}
		if ownerClause != "" {
			args = append(args, ownerArg)
		}
		err := db.QueryRow(h.db, "SELECT COUNT(*) FROM sessions WHERE hwid = ?"+ownerClause, args...).Scan(&count)
		if err == nil {
			resp.Hwid.Count = count
			if count > 1 {
				rows, err := db.Query(h.db, "SELECT id FROM sessions WHERE hwid = ?"+ownerClause+" ORDER BY created_at DESC", args...)
				if err == nil {
					defer rows.Close()
					for rows.Next() {
						var id string
						if rows.Scan(&id) == nil {
							resp.Hwid.Sessions = append(resp.Hwid.Sessions, id)
						}
					}
				}
			}
		}
	}

	if ip != "" {
		var count int
		args := []any{ip}
		if ownerClause != "" {
			args = append(args, ownerArg)
		}
		err := db.QueryRow(h.db, "SELECT COUNT(*) FROM sessions WHERE ip = ?"+ownerClause, args...).Scan(&count)
		if err == nil {
			resp.Ip.Count = count
			if count > 1 {
				rows, err := db.Query(h.db, "SELECT id FROM sessions WHERE ip = ?"+ownerClause+" ORDER BY created_at DESC", args...)
				if err == nil {
					defer rows.Close()
					for rows.Next() {
						var id string
						if rows.Scan(&id) == nil {
							resp.Ip.Sessions = append(resp.Ip.Sessions, id)
						}
					}
				}
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)
}
