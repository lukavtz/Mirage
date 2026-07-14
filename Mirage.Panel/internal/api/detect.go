package api

import (
	"database/sql"
	"net/http"
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

	if hwid != "" {
		var count int
		err := h.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE hwid = ?", hwid).Scan(&count)
		if err == nil {
			resp.Hwid.Count = count
			if count > 1 {
				rows, err := h.db.Query("SELECT id FROM sessions WHERE hwid = ? ORDER BY created_at DESC", hwid)
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
		err := h.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE ip = ?", ip).Scan(&count)
		if err == nil {
			resp.Ip.Count = count
			if count > 1 {
				rows, err := h.db.Query("SELECT id FROM sessions WHERE ip = ? ORDER BY created_at DESC", ip)
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
