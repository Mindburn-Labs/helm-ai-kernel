package api

import (
	"encoding/json"
	"net/http"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// listPublications handles GET /api/research/publications.
func (r *Router) listPublications(w http.ResponseWriter, req *http.Request) {
	pubs, err := r.cfg.Publications.List(req.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if pubs == nil {
		pubs = []researchruntime.PublicationRecord{}
	}
	writeJSON(w, http.StatusOK, pubs)
}

// getPublication handles GET /api/research/publications/{id}.
func (r *Router) getPublication(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	pub, err := r.cfg.Publications.Get(req.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "publication not found")
		return
	}
	writeJSON(w, http.StatusOK, pub)
}

// publishPublication handles POST /api/research/publications/{id}/publish.
// It expects a JSON body containing draft_id and promotion_receipt, and
// delegates to the publication.Service.Promote() method.
func (r *Router) publishPublication(w http.ResponseWriter, req *http.Request) {
	_ = req.PathValue("id")

	// Fail-soft when mounted without a Publication service (read-plane
	// deploys per adr-researchruntime-cmd-helm-mount.md). Return 503 so
	// callers see a specific reason rather than a generic 500/nil-panic.
	if r.cfg.Publication == nil {
		writeError(w, http.StatusServiceUnavailable, "publication service not wired")
		return
	}

	var body struct {
		DraftID string                            `json:"draft_id"`
		Receipt *researchruntime.PromotionReceipt `json:"promotion_receipt"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if body.DraftID == "" {
		writeError(w, http.StatusBadRequest, "draft_id is required")
		return
	}
	if body.Receipt == nil {
		writeError(w, http.StatusBadRequest, "promotion_receipt is required")
		return
	}

	rec, err := r.cfg.Publication.Promote(req.Context(), body.DraftID, body.Receipt)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec)
}
