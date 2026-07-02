package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	_ "modernc.org/sqlite"

	"github.com/user/mirage-panel/internal/api"
	"github.com/user/mirage-panel/internal/db"
	"github.com/user/mirage-panel/internal/middleware"
	"github.com/user/mirage-panel/internal/ws"
)

//go:embed frontend/dist
var frontendFS embed.FS

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func generateSecret() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		slog.Error("failed to generate random secret", "err", err)
		os.Exit(1)
	}
	return hex.EncodeToString(b)
}

func main() {
	port := getEnv("PORT", "8080")
	dbPath := getEnv("DB_PATH", "data/mirage.db")
	jwtSecret := getEnv("JWT_SECRET", "")
	allowedOrigins := getEnv("ALLOWED_ORIGINS", "http://localhost:5173")

	if jwtSecret == "" {
		jwtSecret = generateSecret()
		slog.Warn("JWT_SECRET not set, generated random secret for this session", "secret", jwtSecret)
	}

	slog.Info("starting Mirage Panel",
		"port", port,
		"db", dbPath,
		"allowed_origins", allowedOrigins,
	)

	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		slog.Error("failed to create data directory", "err", err)
		os.Exit(1)
	}

	sqlDB, err := db.OpenDB(dbPath)
	if err != nil {
		slog.Error("failed to open database", "err", err)
		os.Exit(1)
	}
	defer sqlDB.Close()

	if err := db.RunMigrations(sqlDB, db.MigrationsFS); err != nil {
		slog.Error("failed to run migrations", "err", err)
		os.Exit(1)
	}

	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	r.Use(middleware.CORS(allowedOrigins))
	r.Use(middleware.RateLimit(100, time.Minute))
	r.Use(middleware.BanCheck(sqlDB))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	wsHub := ws.NewHub()
	go wsHub.Run()

	r.Get("/ws", ws.ServeWs(wsHub, jwtSecret))

	api.SetupRoutes(r, sqlDB, jwtSecret, allowedOrigins, wsHub)

	distFS, err := fs.Sub(frontendFS, "frontend/dist")
	if err != nil {
		slog.Error("failed to resolve frontend filesystem", "err", err)
		os.Exit(1)
	}

	r.Handle("/assets/*", http.FileServer(http.FS(distFS)))

	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		index, err := fs.ReadFile(distFS, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(index)
	})

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: r,
	}

	go func() {
		slog.Info("listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("forced shutdown", "err", err)
	}

	slog.Info("stopped")
}
