package api

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/user/mirage-panel/internal/services"
)

type LogsHandler struct {
	processor *services.LogProcessor
}

func NewLogsHandler(processor *services.LogProcessor) *LogsHandler {
	return &LogsHandler{processor: processor}
}

func (h *LogsHandler) Ingest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 100<<20)

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "request too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid form data")
		return
	}

	file, _, err := r.FormFile("archive")
	if err != nil {
		writeError(w, http.StatusBadRequest, "archive file required")
		return
	}
	defer file.Close()

	archive, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read archive")
		return
	}

	metadata := r.FormValue("metadata")
	sessionID, err := h.processor.Process(archive, metadata)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "processing failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"session_id": sessionID})
}

var (
	chunkMu  sync.RWMutex
	chunks   = make(map[string]*chunkSession)
	chunkTTL = 1 * time.Hour
)

type chunkSession struct {
	ID        string
	Chunks    map[int][]byte
	CreatedAt time.Time
}

func init() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			chunkMu.Lock()
			for id, cs := range chunks {
				if time.Since(cs.CreatedAt) > chunkTTL {
					delete(chunks, id)
				}
			}
			chunkMu.Unlock()
		}
	}()
}

func (h *LogsHandler) Chunk(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form")
		return
	}

	sessionID := r.FormValue("session_id")
	chunkIdx, _ := strconv.Atoi(r.FormValue("chunk_index"))
	file, _, err := r.FormFile("data")
	if err != nil || sessionID == "" || chunkIdx < 0 {
		writeError(w, http.StatusBadRequest, "invalid chunk data")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read chunk")
		return
	}

	chunkMu.Lock()
	cs, ok := chunks[sessionID]
	if !ok {
		cs = &chunkSession{ID: sessionID, Chunks: make(map[int][]byte), CreatedAt: time.Now()}
		chunks[sessionID] = cs
	}
	cs.Chunks[chunkIdx] = data
	chunkMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]bool{"received": true})
}

func (h *LogsHandler) CompleteChunked(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid form data")
		return
	}

	sessionID := r.FormValue("session_id")
	totalStr := r.FormValue("total_chunks")
	if sessionID == "" || totalStr == "" {
		writeError(w, http.StatusBadRequest, "session_id and total_chunks required")
		return
	}

	total, err := strconv.Atoi(totalStr)
	if err != nil || total < 1 {
		writeError(w, http.StatusBadRequest, "invalid total_chunks")
		return
	}

	chunkMu.Lock()
	cs, ok := chunks[sessionID]
	if !ok {
		chunkMu.Unlock()
		writeError(w, http.StatusBadRequest, "no chunks found for session")
		return
	}
	delete(chunks, sessionID)
	chunkMu.Unlock()

	if len(cs.Chunks) != total {
		writeError(w, http.StatusBadRequest, "chunk count mismatch")
		return
	}

	var archive bytes.Buffer
	for i := 0; i < total; i++ {
		data, ok := cs.Chunks[i]
		if !ok {
			writeError(w, http.StatusBadRequest, "missing chunk "+strconv.Itoa(i))
			return
		}
		archive.Write(data)
	}

	metadata := r.FormValue("metadata")
	newSessionID, err := h.processor.Process(archive.Bytes(), metadata)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "processing failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"session_id": newSessionID})
}
