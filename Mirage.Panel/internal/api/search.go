package api

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type SearchHandler struct {
	db *sql.DB
}

func NewSearchHandler(db *sql.DB) *SearchHandler {
	return &SearchHandler{db: db}
}

type SearchResult struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	SessionID    string `json:"session_id"`
	Field1       string `json:"field1"`
	Field2       string `json:"field2"`
	Field3       string `json:"field3"`
	Field4       string `json:"field4"`
	MatchedField string `json:"matched_field"`
}

func (h *SearchHandler) Search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) < 2 {
		writeError(w, http.StatusBadRequest, "query must be at least 2 characters")
		return
	}

	searchType := r.URL.Query().Get("type")
	if searchType == "" {
		searchType = "all"
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 || limit > 100 {
		limit = 50
	}

	like := "%" + q + "%"

	var unions []string
	var args []any

	if searchType == "all" || searchType == "passwords" {
		unions = append(unions, `
			SELECT id, 'password' as type, session_id,
			       url as field1, username as field2, password_value as field3, browser as field4,
			       CASE
					WHEN url LIKE ? THEN 'url'
					WHEN username LIKE ? THEN 'username'
					ELSE 'password_value'
			       END as matched_field
			FROM passwords
			WHERE url LIKE ? OR username LIKE ? OR password_value LIKE ?`)
		for i := 0; i < 5; i++ {
			args = append(args, like)
		}
	}

	if searchType == "all" || searchType == "cookies" {
		unions = append(unions, `
			SELECT id, 'cookie' as type, session_id,
			       domain as field1, name as field2, value as field3, path as field4,
			       CASE
					WHEN domain LIKE ? THEN 'domain'
					ELSE 'name'
			       END as matched_field
			FROM cookies
			WHERE domain LIKE ? OR name LIKE ?`)
		for i := 0; i < 3; i++ {
			args = append(args, like)
		}
	}

	if searchType == "all" || searchType == "cards" {
		unions = append(unions, `
			SELECT id, 'card' as type, session_id,
			       number as field1, holder as field2, exp_month as field3, exp_year as field4,
			       CASE
					WHEN number LIKE ? THEN 'number'
					ELSE 'holder'
			       END as matched_field
			FROM cards
			WHERE number LIKE ? OR holder LIKE ?`)
		for i := 0; i < 3; i++ {
			args = append(args, like)
		}
	}

	unionSQL := strings.Join(unions, " UNION ALL ")

	var total int
	countArgs := make([]any, len(args))
	copy(countArgs, args)
	countQuery := "SELECT COUNT(*) FROM (" + unionSQL + ")"
	if err := h.db.QueryRow(countQuery, countArgs...).Scan(&total); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to count search results")
		return
	}

	offset := (page - 1) * limit
	query := fmt.Sprintf("%s LIMIT ? OFFSET ?", unionSQL)
	queryArgs := make([]any, len(args)+2)
	copy(queryArgs, args)
	queryArgs[len(args)] = limit
	queryArgs[len(args)+1] = offset

	rows, err := h.db.Query(query, queryArgs...)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to search")
		return
	}
	defer rows.Close()

	results := make([]SearchResult, 0)
	for rows.Next() {
		var res SearchResult
		if err := rows.Scan(
			&res.ID, &res.Type, &res.SessionID,
			&res.Field1, &res.Field2, &res.Field3, &res.Field4,
			&res.MatchedField,
		); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to scan search result")
			return
		}
		results = append(results, res)
	}
	if err := rows.Err(); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to iterate search results")
		return
	}

	pages := (total + limit - 1) / limit

	writeJSON(w, http.StatusOK, map[string]any{
		"results": results,
		"total":   total,
		"page":    page,
		"limit":   limit,
		"pages":   pages,
	})
}
