package middleware

import (
	"database/sql"
	"net/http"
	"sync"
	"time"

	dbutil "zialfi-panel/internal/db"
)

type banEntry struct {
	banned    bool
	expiresAt time.Time
}

type DB interface {
	QueryRow(query string, args ...interface{}) *sql.Row
}

type banChecker struct {
	db    DB
	cache sync.Map
}

func queryBanRow(d DB, query string, args ...any) *sql.Row {
	if raw, ok := d.(*sql.DB); ok {
		return dbutil.QueryRow(raw, query, args...)
	}
	return d.QueryRow(dbutil.Placeholders(query), args...)
}

func BanCheck(db DB) func(http.Handler) http.Handler {
	bc := &banChecker{db: db}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractIP(r)
			hwid := r.Header.Get("X-HWID")

			if cached, ok := bc.cache.Load(ip); ok {
				entry := cached.(banEntry)
				if time.Now().Before(entry.expiresAt) {
					if entry.banned {
						writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
						return
					}
					next.ServeHTTP(w, r)
					return
				}
			}

			var exists bool
			err := queryBanRow(bc.db, "SELECT EXISTS(SELECT 1 FROM bans WHERE ip = ?)", ip).Scan(&exists)
			banned := err == nil && exists

			if !banned && hwid != "" {
				var hwidExists bool
				err := queryBanRow(bc.db, "SELECT EXISTS(SELECT 1 FROM bans WHERE hwid = ?)", hwid).Scan(&hwidExists)
				if err == nil && hwidExists {
					banned = true
				}
			}

			bc.cache.Store(ip, banEntry{
				banned:    banned,
				expiresAt: time.Now().Add(30 * time.Second),
			})

			if banned {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
