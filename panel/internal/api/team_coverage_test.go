package api_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/testutil"
)

func setupTeamRouter(t *testing.T, d *sql.DB) (chi.Router, string) {
	t.Helper()
	jwtSecret := "test-secret"
	r := chi.NewRouter()
	adminID := createTestUser(t, d, "teamadmin", "testpass")
	api.SetupRoutes(r, d, jwtSecret, "*", nil, nil, nil, nil)
	token, _, err := auth.GenerateToken(adminID, "admin", jwtSecret, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	return r, token
}

func TestTeam_List(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTeamRouter(t, d)

	// second user so the list has more than just the admin
	createTestUser(t, d, "teammember", "testpass")

	req := httptest.NewRequest(http.MethodGet, "/api/team", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var members []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &members); err != nil {
		t.Fatal(err)
	}
	if len(members) < 2 {
		t.Errorf("expected at least 2 members, got %d", len(members))
	}
	for _, m := range members {
		if m["username"] == nil || m["role"] == nil {
			t.Errorf("member missing username/role: %v", m)
		}
	}
}

func TestTeam_List_RoleFilter(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTeamRouter(t, d)

	createTestUserWithRole(t, d, "teammember", "testpass", "worker")
	createTestUser(t, d, "teammember2", "testpass") // admin

	req := httptest.NewRequest(http.MethodGet, "/api/team?role=admin", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var members []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &members); err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m["role"] != "admin" {
			t.Errorf("expected only admin members, got role %v", m["role"])
		}
	}
}

func TestTeam_ChangeRole_Valid(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTeamRouter(t, d)

	targetID := createTestUserWithRole(t, d, "targetuser", "testpass", "worker")

	body := bytes.NewBufferString(`{"role": "viewer"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/team/"+targetID+"/role", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var got string
	err := d.QueryRow("SELECT role FROM users WHERE id = $1", targetID).Scan(&got)
	if err != nil {
		t.Fatal(err)
	}
	if got != "viewer" {
		t.Errorf("expected role viewer, got %q", got)
	}
}

func TestTeam_ChangeRole_InvalidRole(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTeamRouter(t, d)

	targetID := createTestUser(t, d, "targetuser", "testpass")

	body := bytes.NewBufferString(`{"role": "superadmin"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/team/"+targetID+"/role", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTeam_ChangeRole_NonexistentUser(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTeamRouter(t, d)

	body := bytes.NewBufferString(`{"role": "viewer"}`)
	req := httptest.NewRequest(http.MethodPut, "/api/team/"+uuid.New().String()+"/role", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTeam_ChangeRole_InvalidJSON(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTeamRouter(t, d)

	targetID := createTestUser(t, d, "targetuser", "testpass")

	body := bytes.NewBufferString(`{not valid json`)
	req := httptest.NewRequest(http.MethodPut, "/api/team/"+targetID+"/role", body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTeam_Remove_Valid(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTeamRouter(t, d)

	targetID := createTestUser(t, d, "doomeduser", "testpass")

	req := httptest.NewRequest(http.MethodDelete, "/api/team/"+targetID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var count int
	err := d.QueryRow("SELECT COUNT(*) FROM users WHERE id = $1", targetID).Scan(&count)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected user deleted, still %d rows", count)
	}
}

func TestTeam_Remove_Nonexistent(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTeamRouter(t, d)

	req := httptest.NewRequest(http.MethodDelete, "/api/team/"+uuid.New().String(), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTeam_Remove_Self(t *testing.T) {
	d := testutil.OpenTestDB(t)
	r, token := setupTeamRouter(t, d)

	// admin token belongs to teamadmin; try removing that same user
	req := httptest.NewRequest(http.MethodDelete, "/api/team/teamadmin-self", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	// resolve the admin user id by username
	var adminID string
	if err := d.QueryRow("SELECT id FROM users WHERE username = 'teamadmin'").Scan(&adminID); err != nil {
		t.Fatal(err)
	}

	req = httptest.NewRequest(http.MethodDelete, "/api/team/"+adminID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}
