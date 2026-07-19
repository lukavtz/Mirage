package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/net/proxy"
)

type ProxyEntry struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	LastCheck string `json:"last_check,omitempty"`
	Alive     bool   `json:"alive"`
}

type ProxyRotator struct {
	mu      sync.RWMutex
	entries []ProxyEntry
	current int
}

func NewProxyRotator(entries []ProxyEntry) *ProxyRotator {
	return &ProxyRotator{entries: entries}
}

func (r *ProxyRotator) Add(entry ProxyEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	r.entries = append(r.entries, entry)
}

func (r *ProxyRotator) Remove(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, e := range r.entries {
		if e.ID == id {
			r.entries = append(r.entries[:i], r.entries[i+1:]...)
			if r.current >= len(r.entries) {
				r.current = 0
			}
			return true
		}
	}
	return false
}

func (r *ProxyRotator) List() []ProxyEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProxyEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

func (r *ProxyRotator) Next() *ProxyEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		return nil
	}
	entry := &r.entries[r.current]
	r.current = (r.current + 1) % len(r.entries)
	return entry
}

func (r *ProxyRotator) NextAlive() *ProxyEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		return nil
	}
	for i := 0; i < len(r.entries); i++ {
		idx := (r.current + i) % len(r.entries)
		if r.entries[idx].Alive {
			r.current = (idx + 1) % len(r.entries)
			return &r.entries[idx]
		}
	}
	return nil
}

func (r *ProxyRotator) MarkAlive(id string, alive bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.entries {
		if r.entries[i].ID == id {
			r.entries[i].Alive = alive
			r.entries[i].LastCheck = time.Now().UTC().Format(time.RFC3339)
			return
		}
	}
}

func (r *ProxyRotator) HealthCheck(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	check := func() {
		for _, e := range r.List() {
			alive := testProxy(e)
			r.MarkAlive(e.ID, alive)
		}
	}

	check()
	for {
		select {
		case <-ticker.C:
			check()
		case <-ctx.Done():
			return
		}
	}
}

func testProxy(entry ProxyEntry) bool {
	addr := fmt.Sprintf("%s:%d", entry.Host, entry.Port)
	dialer, err := proxy.SOCKS5("tcp", addr, nil, proxy.Direct)
	if err != nil {
		return false
	}
	conn, err := dialer.Dial("tcp", "8.8.8.8:53")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func SOCKS5Transport(proxyAddr string) (*http.Transport, error) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("socks5 dialer: %w", err)
	}
	return &http.Transport{
		Dial: dialer.Dial,
	}, nil
}

const defaultProxyStoreKey = "proxies"

func LoadProxies(db interface {
	Get(key string) (string, error)
}) ([]ProxyEntry, error) {
	raw, err := db.Get(defaultProxyStoreKey)
	if err != nil {
		return nil, err
	}
	if raw == "" {
		return nil, nil
	}
	var entries []ProxyEntry
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].ID == "" {
			entries[i].ID = uuid.New().String()
		}
	}
	return entries, nil
}

func SaveProxies(db interface{ Set(key, value string) error }, entries []ProxyEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return db.Set(defaultProxyStoreKey, string(data))
}

type ProxyStore interface {
	Get(key string) (string, error)
	Set(key, value string) error
}

type ProxyRotatorHandler struct {
	rotator *ProxyRotator
	store   ProxyStore
}

func NewProxyRotatorHandler(rotator *ProxyRotator, store ProxyStore) *ProxyRotatorHandler {
	return &ProxyRotatorHandler{rotator: rotator, store: store}
}

func (h *ProxyRotatorHandler) ListProxies(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.rotator.List())
}

func (h *ProxyRotatorHandler) AddProxy(w http.ResponseWriter, r *http.Request) {
	var entry ProxyEntry
	if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if entry.Host == "" || entry.Port == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "host and port are required"})
		return
	}
	if entry.Type == "" {
		entry.Type = "socks5"
	}
	entry.ID = uuid.New().String()
	h.rotator.Add(entry)
	if h.store != nil {
		h.store.Set(defaultProxyStoreKey, marshalProxies(h.rotator.List()))
	}
	writeJSON(w, http.StatusCreated, entry)
}

func (h *ProxyRotatorHandler) DeleteProxy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}
	if !h.rotator.Remove(id) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy not found"})
		return
	}
	if h.store != nil {
		h.store.Set(defaultProxyStoreKey, marshalProxies(h.rotator.List()))
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "proxy deleted"})
}

type settingsStore struct {
	get func(string) (string, error)
	set func(string, string) error
}

func (s *settingsStore) Get(key string) (string, error) { return s.get(key) }
func (s *settingsStore) Set(key, value string) error    { return s.set(key, value) }

func NewSettingsStore(getter func(string) (string, error), setter func(string, string) error) ProxyStore {
	return &settingsStore{get: getter, set: setter}
}

func marshalProxies(entries []ProxyEntry) string {
	data, _ := json.Marshal(entries)
	return string(data)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

var _ ProxyStore = (*settingsStore)(nil)
