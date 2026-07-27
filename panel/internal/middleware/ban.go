package middleware

import (
	"database/sql"
	"net/http"
	"sync"
	"time"
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
			err := bc.db.QueryRow("SELECT EXISTS(SELECT 1 FROM bans WHERE ip = ?)", ip).Scan(&exists)
			banned := err == nil && exists

			if !banned && hwid != "" {
				var hwidExists bool
				err := bc.db.QueryRow("SELECT EXISTS(SELECT 1 FROM bans WHERE hwid = ?)", hwid).Scan(&hwidExists)
				if err == nil && hwidExists {
					banned = true
				}
			}

			bc.cache.Store(ip, banEntry{
				banned:    banned,
				expiresAt: time.Now().Add(5 * time.Minute),
			})

			if banned {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
