package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "mirage-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	d, err := db.OpenDB(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.RunMigrations(d, db.MigrationsFS); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func createTestUser(t *testing.T, d *sql.DB, username, password string) string {
	t.Helper()
	id := uuid.New().String()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Exec("INSERT INTO users (id, username, password_hash, role) VALUES (?, ?, ?, ?)",
		id, username, hash, "admin")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestLogAudit_Success(t *testing.T) {
	d := openTestDB(t)
	uid := createTestUser(t, d, "audit-log-user", "password123")

	LogAudit(d, uid, "test.action", "test details", "1.2.3.4")

	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND action = ?", uid, "test.action").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 audit row, got %d", count)
	}

	var details, ip string
	err = d.QueryRow("SELECT details, ip FROM audit_log WHERE user_id = ? AND action = ?", uid, "test.action").Scan(&details, &ip)
	if err != nil {
		t.Fatal(err)
	}
	if details != "test details" {
		t.Errorf("expected details 'test details', got %q", details)
	}
	if ip != "1.2.3.4" {
		t.Errorf("expected ip '1.2.3.4', got %q", ip)
	}
}

func TestLogAudit_DBError(t *testing.T) {
	// Close the DB immediately so any Exec call fails with an error (not panic).
	d := openTestDB(t)
	d.Close()

	// Should not panic, just log the error via slog.
	LogAudit(d, "some-user", "test.action", "details", "1.2.3.4")
	// If we got here without panic, the test passes.
}

func TestLogWorkerAction_WithTarget(t *testing.T) {
	d := openTestDB(t)
	uid := createTestUser(t, d, "worker-audit-user", "password123")
	targetID := uuid.New().String()

	target := &targetID
	LogWorkerAction(d, uid, "worker.action", "worker details", "5.6.7.8", target)

	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND action = ? AND target_user_id = ?",
		uid, "worker.action", targetID).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 worker action row, got %d", count)
	}
}

func TestLogWorkerAction_NilTarget(t *testing.T) {
	d := openTestDB(t)
	uid := createTestUser(t, d, "worker-nil-target", "password123")

	LogWorkerAction(d, uid, "worker.action.nil", "no target", "9.9.9.9", nil)

	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM audit_log WHERE user_id = ? AND action = ? AND target_user_id IS NULL",
		uid, "worker.action.nil").Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 row with nil target, got %d", count)
	}
}

func TestJoinConditions_Empty(t *testing.T) {
	got := joinConditions(nil)
	if got != "1=1" {
		t.Errorf("joinConditions(nil) = %q, want %q", got, "1=1")
	}

	got = joinConditions([]string{})
	if got != "1=1" {
		t.Errorf("joinConditions([]) = %q, want %q", got, "1=1")
	}
}

func TestJoinConditions_Single(t *testing.T) {
	got := joinConditions([]string{"user_id = ?"})
	if got != "user_id = ?" {
		t.Errorf("joinConditions(single) = %q, want %q", got, "user_id = ?")
	}
}

func TestJoinConditions_Multiple(t *testing.T) {
	got := joinConditions([]string{"user_id = ?", "action = ?"})
	want := "user_id = ? AND action = ?"
	if got != want {
		t.Errorf("joinConditions(multiple) = %q, want %q", got, want)
	}
}

func TestAuditStats_AdminOK(t *testing.T) {
	d := openTestDB(t)
	uid := createTestUser(t, d, "audit-stats-admin", "password123")
	handler := NewAuditHandler(d, db.ProviderSQLite)

	req := httptest.NewRequest(http.MethodGet, "/?worker_id="+uid, nil)
	claims := &auth.Claims{UserID: uid, Role: "admin"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()

	handler.Stats(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp struct {
		SessionsViewed int `json:"sessions_viewed"`
		Exports        int `json:"exports"`
		Locks          int `json:"locks"`
		Comments       int `json:"comments"`
		Total          int `json:"total"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 0 {
		t.Errorf("expected 0 total, got %d", resp.Total)
	}
}

func TestAuditStats_NoAuth(t *testing.T) {
	d := openTestDB(t)
	handler := NewAuditHandler(d, db.ProviderSQLite)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.Stats(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestAuditStats_NotAdmin_DifferentWorker(t *testing.T) {
	d := openTestDB(t)
	uid := createTestUser(t, d, "audit-stats-user", "password123")
	handler := NewAuditHandler(d, db.ProviderSQLite)

	// Requesting stats for a different worker_id while being a regular user.
	req := httptest.NewRequest(http.MethodGet, "/?worker_id=some-other-worker", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()

	handler.Stats(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}