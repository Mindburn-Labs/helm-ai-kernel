package api

import (
	"encoding/json"
	"net/http"
)

// listOverrides handles GET /api/research/overrides.
// Returns all pending override requests.
func (r *Router) listOverrides(w http.ResponseWriter, req *http.Request) {
	overrides, err := r.cfg.Overrides.ListPending(req.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if overrides == nil {
		overrides = nil // empty slice — callers handle null gracefully
	}
	writeJSON(w, http.StatusOK, overrides)
}

// resolveOverride handles POST /api/research/overrides/{id}/resolve.
// Body: {"decision": "approve"|"reject", "operator_id": "...", "notes": "..."}
func (r *Router) resolveOverride(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")

	var body struct {
		Decision   string `json:"decision"`
		OperatorID string `json:"operator_id"`
		Notes      string `json:"notes,omitempty"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if body.Decision == "" {
		writeError(w, http.StatusBadRequest, "decision is required")
		return
	}
	if body.OperatorID == "" {
		writeError(w, http.StatusBadRequest, "operator_id is required")
		return
	}

	if err := r.cfg.Overrides.Resolve(req.Context(), id, body.Decision, body.OperatorID, body.Notes); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "resolved"})
}
