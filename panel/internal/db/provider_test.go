package db

import (
	"testing"
	"time"
)

func TestPostgresConnMaxLifetimeIsFinite(t *testing.T) {
	if postgresConnMaxLifetime <= 0 || postgresConnMaxLifetime > 30*time.Minute {
		t.Fatalf("postgres connection max lifetime = %s, want between 0 and 30m", postgresConnMaxLifetime)
	}
}
