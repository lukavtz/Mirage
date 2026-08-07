package db

import (
	"database/sql"
	"fmt"
	"runtime"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// postgresConnMaxLifetime bounds how long a pooled connection is reused.
const postgresConnMaxLifetime = 30 * time.Minute

// OpenPostgres opens and verifies a PostgreSQL connection pool.
func OpenPostgres(connString string) (*sql.DB, error) {
	db, err := sql.Open("pgx", connString)
	if err != nil {
		return nil, fmt.Errorf("open postgres: %w", err)
	}
	pool := runtime.NumCPU() * 4
	if pool < 8 {
		pool = 8
	}
	db.SetMaxOpenConns(pool)
	db.SetMaxIdleConns(pool / 2)
	db.SetConnMaxIdleTime(5 * time.Minute)
	db.SetConnMaxLifetime(postgresConnMaxLifetime)
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return db, nil
}
