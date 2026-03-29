package api

import (
	"net/http"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// listSources handles GET /api/research/missions/{id}/sources.
func (r *Router) listSources(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	sources, err := r.cfg.Sources.ListByMission(req.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if sources == nil {
		sources = []researchruntime.SourceSnapshot{}
	}
	writeJSON(w, http.StatusOK, sources)
}
