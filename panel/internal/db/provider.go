package db

import (
	"database/sql"
	"runtime"
	"time"
	"fmt"
	"io/fs"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type ProviderType string

const (
	ProviderSQLite   ProviderType = "sqlite"
	ProviderPostgres ProviderType = "postgres"
)

type Provider interface {
	Open() (*sql.DB, error)
	RunMigrations(db *sql.DB, migrationsDir string) error
	Type() ProviderType
}

func NewProvider(providerType ProviderType, connString string) Provider {
	switch providerType {
	case ProviderPostgres:
		return &PostgresProvider{connString: connString}
	default:
		return &SQLiteProvider{path: connString}
	}
}

type SQLiteProvider struct {
	path string
}

func (p *SQLiteProvider) Open() (*sql.DB, error) {
	return OpenDB(p.path)
}

func (p *SQLiteProvider) RunMigrations(d *sql.DB, migrationsDir string) error {
	return RunMigrations(d, MigrationsFS)
}

func (p *SQLiteProvider) Type() ProviderType {
	return ProviderSQLite
}

type PostgresProvider struct {
	connString string
}

func (p *PostgresProvider) Open() (*sql.DB, error) {
	db, err := sql.Open("pgx", p.connString)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	// PG handles concurrent connections well; SQLite does not (it is kept
	// at 1 in OpenDB). Tie the pool to CPU count so stealer ingest bursts
	// (parallel /api/log uploads) don't serialize on a tiny pool. Idle
	// connections are capped so a quiet panel doesn't squat on PG slots.
	pool := runtime.NumCPU() * 4
	if pool < 8 {
		pool = 8
	}
	db.SetMaxOpenConns(pool)
	db.SetMaxIdleConns(pool / 2)
	db.SetConnMaxIdleTime(5 * time.Minute)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return db, nil
}

func (p *PostgresProvider) RunMigrations(d *sql.DB, migrationsDir string) error {
	dir := fs.FS(MigrationsFS)
	return RunMigrations(d, dir)
}

func (p *PostgresProvider) Type() ProviderType {
	return ProviderPostgres
}
