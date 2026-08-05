package services_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"zialfi-panel/internal/services"
)

type stubStore struct {
	mu   sync.Mutex
	data map[string]string
	err  error
}

func (s *stubStore) Get(key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return "", s.err
	}
	return s.data[key], nil
}

func (s *stubStore) Set(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.data[key] = value
	return nil
}

func TestProxyRotator_Add(t *testing.T) {
	r := services.NewProxyRotator(nil)
	r.Add(services.ProxyEntry{ID: "1", Host: "h1", Port: 1080})
	if got := r.Next(); got == nil || got.ID != "1" {
		t.Fatalf("expected added entry, got %+v", got)
	}
	r.Add(services.ProxyEntry{Host: "h2", Port: 1080})
	next := r.Next()
	if next.ID == "" {
		t.Error("expected auto-generated ID")
	}
}

func TestProxyRotator_Remove(t *testing.T) {
	entries := []services.ProxyEntry{
		{ID: "a", Host: "ha"}, {ID: "b", Host: "hb"}, {ID: "c", Host: "hc"},
	}
	r := services.NewProxyRotator(entries)
	if !r.Remove("b") {
		t.Fatal("expected removal")
	}
	list := r.List()
	if len(list) != 2 || list[0].ID != "a" || list[1].ID != "c" {
		t.Errorf("unexpected list after removal: %+v", list)
	}
	if r.Remove("nonexistent") {
		t.Error("should return false for nonexistent")
	}
}

func TestProxyRotator_Remove_OnlyElement(t *testing.T) {
	r := services.NewProxyRotator([]services.ProxyEntry{{ID: "only", Host: "h"}})
	r.Next()
	r.Remove("only")
	if r.Next() != nil {
		t.Error("rotator should be empty")
	}
}

func TestProxyRotator_List(t *testing.T) {
	entries := []services.ProxyEntry{{ID: "1", Host: "h"}, {ID: "2", Host: "h2"}}
	r := services.NewProxyRotator(entries)
	list := r.List()
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2", len(list))
	}
	list[0].Host = "mutated"
	if r.Next().Host != "h" {
		t.Error("List should return a copy")
	}
}

func TestProxyRotator_NextAlive(t *testing.T) {
	entries := []services.ProxyEntry{
		{ID: "dead1", Host: "d1", Alive: false},
		{ID: "alive1", Host: "a1", Alive: true},
		{ID: "dead2", Host: "d2", Alive: false},
		{ID: "alive2", Host: "a2", Alive: true},
	}
	r := services.NewProxyRotator(entries)
	got := r.NextAlive()
	if got == nil || got.ID != "alive1" {
		t.Fatalf("expected alive1, got %+v", got)
	}
	got = r.NextAlive()
	if got == nil || got.ID != "alive2" {
		t.Fatalf("expected alive2, got %+v", got)
	}
	got = r.NextAlive()
	if got == nil || got.ID != "alive1" {
		t.Fatalf("expected alive1 (wrap), got %+v", got)
	}
}

func TestProxyRotator_NextAlive_None(t *testing.T) {
	entries := []services.ProxyEntry{
		{ID: "d1", Host: "d", Alive: false},
		{ID: "d2", Host: "d", Alive: false},
	}
	r := services.NewProxyRotator(entries)
	if got := r.NextAlive(); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestProxyRotator_NextAlive_Empty(t *testing.T) {
	r := services.NewProxyRotator(nil)
	if got := r.NextAlive(); got != nil {
		t.Error("expected nil for empty rotator")
	}
}

func TestProxyRotator_MarkAlive(t *testing.T) {
	entries := []services.ProxyEntry{{ID: "p1", Host: "h"}}
	r := services.NewProxyRotator(entries)
	r.MarkAlive("p1", true)
	next := r.Next()
	if next == nil || !next.Alive {
		t.Error("p1 should be marked alive")
	}
	if next.LastCheck == "" {
		t.Error("LastCheck should be set")
	}
	r.MarkAlive("nonexistent", true)
}

func TestProxyRotator_HealthCheck(t *testing.T) {
	entries := []services.ProxyEntry{
		{ID: "p1", Host: "127.0.0.1", Port: 1},
	}
	r := services.NewProxyRotator(entries)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r.HealthCheck(ctx, 10*time.Millisecond)
	list := r.List()
	if len(list) > 0 && list[0].LastCheck == "" {
		t.Error("HealthCheck should mark entries with LastCheck")
	}
}

func TestLoadProxies_Success(t *testing.T) {
	store := &stubStore{data: map[string]string{
		"proxies": `[{"id":"x","host":"h","port":1080}]`,
	}}
	entries, err := services.LoadProxies(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Host != "h" {
		t.Errorf("unexpected entries: %+v", entries)
	}
}

func TestLoadProxies_Empty(t *testing.T) {
	store := &stubStore{data: map[string]string{"proxies": ""}}
	entries, err := services.LoadProxies(store)
	if err != nil {
		t.Fatal(err)
	}
	if entries != nil {
		t.Errorf("expected nil, got %+v", entries)
	}
}

func TestLoadProxies_InvalidJSON(t *testing.T) {
	store := &stubStore{data: map[string]string{"proxies": "not-json"}}
	_, err := services.LoadProxies(store)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestLoadProxies_GetError(t *testing.T) {
	store := &stubStore{err: errors.New("boom")}
	_, err := services.LoadProxies(store)
	if err == nil {
		t.Fatal("expected error from store")
	}
}

func TestLoadProxies_FillsMissingIDs(t *testing.T) {
	store := &stubStore{data: map[string]string{
		"proxies": `[{"host":"h","port":1080},{"id":"has-id","host":"h2","port":1081}]`,
	}}
	entries, err := services.LoadProxies(store)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].ID == "" {
		t.Error("first entry should have been assigned an ID")
	}
	if entries[1].ID != "has-id" {
		t.Error("second entry should keep its ID")
	}
}

func TestSaveProxies_Success(t *testing.T) {
	store := &stubStore{data: make(map[string]string)}
	entries := []services.ProxyEntry{{ID: "1", Host: "h", Port: 1080}}
	if err := services.SaveProxies(store, entries); err != nil {
		t.Fatal(err)
	}
	if store.data["proxies"] == "" {
		t.Error("expected proxies to be stored")
	}
}

func TestSaveProxies_SetError(t *testing.T) {
	store := &stubStore{err: errors.New("boom")}
	err := services.SaveProxies(store, []services.ProxyEntry{{ID: "1", Host: "h"}})
	if err == nil {
		t.Fatal("expected error from store")
	}
}

func TestProxyRotator_ListProxies(t *testing.T) {
	entries := []services.ProxyEntry{{ID: "1", Host: "h"}}
	r := services.NewProxyRotator(entries)
	handler := services.NewProxyRotatorHandler(r, nil)
	req := httptest.NewRequest("GET", "/proxies", nil)
	w := httptest.NewRecorder()
	handler.ListProxies(w, req)
	if w.Code != 200 {
		t.Errorf("status = %d, want 200", w.Code)
	}
	var got []services.ProxyEntry
	json.NewDecoder(w.Body).Decode(&got)
	if len(got) != 1 || got[0].ID != "1" {
		t.Errorf("unexpected response: %+v", got)
	}
}

func TestProxyRotator_AddProxy(t *testing.T) {
	store := &stubStore{data: make(map[string]string)}
	r := services.NewProxyRotator(nil)
	handler := services.NewProxyRotatorHandler(r, store)

	body := strings.NewReader(`{"host":"10.0.0.1","port":1080,"type":"socks5"}`)
	req := httptest.NewRequest("POST", "/proxies", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.AddProxy(w, req)
	if w.Code != 201 {
		t.Errorf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var entry services.ProxyEntry
	json.NewDecoder(w.Body).Decode(&entry)
	if entry.Host != "10.0.0.1" || entry.Type != "socks5" {
		t.Errorf("unexpected entry: %+v", entry)
	}
	if store.data["proxies"] == "" {
		t.Error("store should have been updated")
	}
}

func TestProxyRotator_AddProxy_Defaults(t *testing.T) {
	r := services.NewProxyRotator(nil)
	handler := services.NewProxyRotatorHandler(r, nil)
	body := strings.NewReader(`{"host":"10.0.0.1","port":1080}`)
	req := httptest.NewRequest("POST", "/proxies", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.AddProxy(w, req)
	if w.Code != 201 {
		t.Errorf("status = %d, want 201; body: %s", w.Code, w.Body.String())
	}
	var entry services.ProxyEntry
	json.NewDecoder(w.Body).Decode(&entry)
	if entry.Type != "socks5" {
		t.Errorf("default type should be socks5, got %q", entry.Type)
	}
}

func TestProxyRotator_AddProxy_InvalidJSON(t *testing.T) {
	handler := services.NewProxyRotatorHandler(services.NewProxyRotator(nil), nil)
	body := strings.NewReader(`{bad json`)
	req := httptest.NewRequest("POST", "/proxies", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.AddProxy(w, req)
	if w.Code != 400 {
		t.Errorf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestProxyRotator_AddProxy_MissingHost(t *testing.T) {
	handler := services.NewProxyRotatorHandler(services.NewProxyRotator(nil), nil)
	body := strings.NewReader(`{"port":1080}`)
	req := httptest.NewRequest("POST", "/proxies", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.AddProxy(w, req)
	if w.Code != 400 {
		t.Errorf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestProxyRotator_DeleteProxy(t *testing.T) {
	store := &stubStore{data: make(map[string]string)}
	entries := []services.ProxyEntry{{ID: "1", Host: "h"}}
	r := services.NewProxyRotator(entries)
	handler := services.NewProxyRotatorHandler(r, store)

	req := httptest.NewRequest("DELETE", "/proxies/1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	handler.DeleteProxy(w, req)
	if w.Code != 200 {
		t.Errorf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	if store.data["proxies"] == "" {
		t.Error("store should have been updated after delete")
	}
}

func TestProxyRotator_DeleteProxy_NotFound(t *testing.T) {
	entries := []services.ProxyEntry{{ID: "1", Host: "h"}}
	r := services.NewProxyRotator(entries)
	handler := services.NewProxyRotatorHandler(r, nil)

	req := httptest.NewRequest("DELETE", "/proxies/nonexistent", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "nonexistent")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	handler.DeleteProxy(w, req)
	if w.Code != 404 {
		t.Errorf("status = %d, want 404; body: %s", w.Code, w.Body.String())
	}
}

func TestProxyRotator_DeleteProxy_MissingID(t *testing.T) {
	handler := services.NewProxyRotatorHandler(services.NewProxyRotator(nil), nil)
	req := httptest.NewRequest("DELETE", "/proxies", nil)
	w := httptest.NewRecorder()
	handler.DeleteProxy(w, req)
	if w.Code != 400 {
		t.Errorf("status = %d, want 400; body: %s", w.Code, w.Body.String())
	}
}

func TestNewSettingsStore(t *testing.T) {
	var getKey, setKey string
	var setVal string
	getter := func(k string) (string, error) { getKey = k; return "v", nil }
	setter := func(k, v string) error { setKey = k; setVal = v; return nil }

	s := services.NewSettingsStore(getter, setter)
	v, err := s.Get("k")
	if err != nil || v != "v" || getKey != "k" {
		t.Errorf("Get: v=%q, err=%v, key=%q", v, err, getKey)
	}
	if err := s.Set("k2", "v2"); err != nil || setKey != "k2" || setVal != "v2" {
		t.Errorf("Set: key=%q, val=%q", setKey, setVal)
	}
}