package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/auth"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/middleware"
	"zialfi-panel/internal/services"
)

func TestBuild_UpdateTag_Extra(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	buildID := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO builds (id, config_hash, file_size, file_data, sha256, build_tag, module_config)
		VALUES (?, 'hash', 4, x'01020304', 'sha', 'original', '{}')`, buildID); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Put("/api/build/{id}/tag", handler.UpdateTag)

	updateBody := `{"tag":"updated-tag"}`
	req2 := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/build/%s/tag", buildID), strings.NewReader(updateBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("update: expected 200, got %d: %s", w2.Code, w2.Body.String())
	}

	var updateResp map[string]any
	if err := json.Unmarshal(w2.Body.Bytes(), &updateResp); err != nil {
		t.Fatal(err)
	}
	if updateResp["build_tag"] != "updated-tag" {
		t.Errorf("build_tag = %v, want %q", updateResp["build_tag"], "updated-tag")
	}

	var tag string
	if err := d.QueryRow("SELECT build_tag FROM builds WHERE id = ?", buildID).Scan(&tag); err != nil {
		t.Fatal(err)
	}
	if tag != "updated-tag" {
		t.Errorf("persisted build_tag = %q, want %q", tag, "updated-tag")
	}
}

func TestBuild_UpdateTag_MissingID_Extra(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Put("/api/build/{id}/tag", handler.UpdateTag)

	req := httptest.NewRequest(http.MethodPut, "/api/build//tag", strings.NewReader(`{"tag":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBuild_UpdateTag_NotFound_Extra(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	r := chi.NewRouter()
	r.Put("/api/build/{id}/tag", handler.UpdateTag)

	body := `{"tag":"newtag"}`
	req := httptest.NewRequest(http.MethodPut, "/api/build/nonexistent-id/tag", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBuild_UploadIcon(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	buildID := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO builds (id, config_hash, file_size, file_data, sha256, build_tag, module_config)
		VALUES (?, 'hash', 4, x'01020304', 'sha', '', '{}')`, buildID); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("icon", "icon.ico")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("fake-icon-data")); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/build/{id}/icon", handler.UploadIcon)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/build/%s/icon", buildID), &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["id"] != buildID {
		t.Errorf("id = %v, want %q", resp["id"], buildID)
	}

	// Cleanup the icon file written to data/icons
	iconPath := filepath.Join("data", "icons", buildID+".ico")
	os.Remove(iconPath)
}

func TestBuild_UploadIcon_NoFile(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	buildID := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO builds (id, config_hash, file_size, file_data, sha256, build_tag, module_config)
		VALUES (?, 'hash', 4, x'01020304', 'sha', '', '{}')`, buildID); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/build/{id}/icon", handler.UploadIcon)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/build/%s/icon", buildID), &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBuild_UpdateTag_Forbidden(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	uid := createTestUserWithRole(t, d, "buildowner", "pass", "user")
	buildID := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO builds (id, config_hash, file_size, file_data, sha256, build_tag, module_config, user_id)
		VALUES (?, 'hash', 4, x'01020304', 'sha', '', '{}', ?)`, buildID, uid); err != nil {
		t.Fatal(err)
	}

	// Another user (not admin, not owner) cannot update the tag
	other := createTestUserWithRole(t, d, "buildother", "pass", "user")

	r := chi.NewRouter()
	r.Put("/api/build/{id}/tag", handler.UpdateTag)

	body := `{"tag":"hijack"}`
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/api/build/%s/tag", buildID), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	claims := &auth.Claims{UserID: other, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBuild_C2HostTooLong(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	longHost := strings.Repeat("a", 257)
	body := `{"c2_host":"` + longHost + `","c2_port":4444}`
	req := httptest.NewRequest(http.MethodPost, "/api/build", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Build(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBuild_C2PortOutOfRange(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	cases := []string{`{"c2_host":"h","c2_port":0}`, `{"c2_host":"h","c2_port":65536}`, `{"c2_host":"h","c2_port":-1}`}
	for _, body := range cases {
		req := httptest.NewRequest(http.MethodPost, "/api/build", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.Build(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("body %s: expected 400, got %d: %s", body, w.Code, w.Body.String())
		}
	}
}

func TestBuild_InvalidJSON(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	req := httptest.NewRequest(http.MethodPost, "/api/build", strings.NewReader(`not json`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Build(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBuild_Stats_NonAdmin(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	uid := createTestUserWithRole(t, d, "statsowner", "pass", "user")
	buildID := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO builds (id, config_hash, file_size, file_data, sha256, build_tag, module_config, user_id)
		VALUES (?, 'hash', 4, x'01020304', 'sha', 'tag1', '{}', ?)`, buildID, uid); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Get("/api/build/stats", handler.Stats)

	req := httptest.NewRequest(http.MethodGet, "/api/build/stats", nil)
	claims := &auth.Claims{UserID: uid, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	builds, _ := resp["builds"].([]any)
	if len(builds) != 1 {
		t.Errorf("expected 1 build in stats, got %d", len(builds))
	}
	totalDownloads, _ := resp["total_downloads"].(float64)
	if totalDownloads != 0 {
		t.Errorf("total_downloads = %v, want 0", totalDownloads)
	}
}

func TestBuild_UploadIcon_InvalidMultipart(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	buildID := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO builds (id, config_hash, file_size, file_data, sha256, build_tag, module_config)
		VALUES (?, 'hash', 4, x'01020304', 'sha', '', '{}')`, buildID); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/build/{id}/icon", handler.UploadIcon)

	// Garbage body with multipart content type -> ParseMultipartForm fails
	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/build/%s/icon", buildID), strings.NewReader("not a multipart body"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=xyz")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBuild_UploadIcon_MissingID(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	req := httptest.NewRequest(http.MethodPost, "/api/build//icon", nil)
	w := httptest.NewRecorder()
	handler.UploadIcon(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBuild_UploadIcon_Forbidden(t *testing.T) {
	d := openTestDB(t)
	svc := services.NewBuildService()
	handler := api.NewBuildHandler(svc, []byte{}, []byte{}, d, db.ProviderSQLite)

	owner := createTestUserWithRole(t, d, "iconowner", "pass", "user")
	other := createTestUserWithRole(t, d, "iconother", "pass", "user")

	buildID := uuid.New().String()
	if _, err := d.Exec(`INSERT INTO builds (id, config_hash, file_size, file_data, sha256, build_tag, module_config, user_id)
		VALUES (?, 'hash', 4, x'01020304', 'sha', '', '{}', ?)`, buildID, owner); err != nil {
		t.Fatal(err)
	}

	r := chi.NewRouter()
	r.Post("/api/build/{id}/icon", handler.UploadIcon)

	req := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/api/build/%s/icon", buildID), nil)
	claims := &auth.Claims{UserID: other, Role: "user"}
	req = req.WithContext(middleware.ContextWithClaims(req.Context(), claims))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}
