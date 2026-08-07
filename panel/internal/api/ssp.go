package api

import (
	"io"
	"net/http"

	"zialfi-panel/internal/services"
)

type SSPHandler struct {
	processor *services.LogProcessor
}

func NewSSPHandler(processor *services.LogProcessor) *SSPHandler {
	return &SSPHandler{processor: processor}
}

func (h *SSPHandler) ProcessSSP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 55<<20)

	archive, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read body")
		return
	}

	if len(archive) == 0 {
		writeError(w, http.StatusBadRequest, "empty archive")
		return
	}

	sessionID, err := h.processor.Process(archive, "", claimsUserID(r))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid archive")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"session_id": sessionID})
}
