package api

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/user/mirage-panel/internal/auth"
	"github.com/user/mirage-panel/internal/ws"
)

type ctxKey string

const claimsKey ctxKey = "claims"

func AuthMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" || !strings.HasPrefix(header, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			tokenStr := strings.TrimPrefix(header, "Bearer ")
			claims, err := auth.ValidateToken(tokenStr, secret)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), claimsKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func CORSMiddleware(allowedOrigins string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			if allowedOrigins == "*" {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else {
				for _, o := range strings.Split(allowedOrigins, ",") {
					if strings.TrimSpace(o) == origin {
						w.Header().Set("Access-Control-Allow-Origin", origin)
						break
					}
				}
			}

			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func SetupRoutes(r chi.Router, db *sql.DB, jwtSecret string, allowedOrigins string, hub *ws.Hub) {
	authHandler := NewAuthHandler(db, jwtSecret)
	statsHandler := NewStatsHandler(db, hub)

	r.Use(CORSMiddleware(allowedOrigins))

	r.Group(func(r chi.Router) {
		r.Post("/api/auth/login", authHandler.Login)
	})

	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(jwtSecret))
		r.Get("/api/stats", statsHandler.Dashboard)

		sessionsHandler := NewSessionsHandler(db)
		r.Get("/api/sessions", sessionsHandler.List)
		r.Get("/api/sessions/{id}", sessionsHandler.Detail)
		r.Delete("/api/sessions/{id}", sessionsHandler.Delete)
	})
}
