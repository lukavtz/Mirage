package api

import (
	"net/http"
	"runtime"
)

type SystemHealthHandler struct{}

func NewSystemHealthHandler() *SystemHealthHandler {
	return &SystemHealthHandler{}
}

type SystemHealthResponse struct {
	Status     string `json:"status"`
	GoRoutines int    `json:"goroutines"`
	MemAlloc   uint64 `json:"mem_alloc_mb"`
	MemSys     uint64 `json:"mem_sys_mb"`
	MemHeap    uint64 `json:"mem_heap_mb"`
	GCCycles   uint32 `json:"gc_cycles"`
	Version    string `json:"go_version"`
}

func (h *SystemHealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	writeJSON(w, http.StatusOK, SystemHealthResponse{
		Status:     "ok",
		GoRoutines: runtime.NumGoroutine(),
		MemAlloc:   m.Alloc / 1024 / 1024,
		MemSys:     m.Sys / 1024 / 1024,
		MemHeap:    m.HeapAlloc / 1024 / 1024,
		GCCycles:   m.NumGC,
		Version:    runtime.Version(),
	})
}
