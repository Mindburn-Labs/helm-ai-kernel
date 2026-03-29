package api

import (
	"net/http"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
)

// listTasks handles GET /api/research/missions/{id}/tasks.
func (r *Router) listTasks(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	tasks, err := r.cfg.Tasks.ListByMission(req.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tasks == nil {
		tasks = []researchruntime.TaskLease{}
	}
	writeJSON(w, http.StatusOK, tasks)
}

// listDrafts handles GET /api/research/missions/{id}/drafts.
func (r *Router) listDrafts(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	drafts, err := r.cfg.Drafts.ListByMission(req.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if drafts == nil {
		drafts = []researchruntime.DraftManifest{}
	}
	writeJSON(w, http.StatusOK, drafts)
}
