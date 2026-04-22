package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
	"github.com/google/uuid"
)

// createMission handles POST /api/research/missions.
// It accepts a simplified request body and creates a MissionSpec record.
func (r *Router) createMission(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Type      string `json:"type"`
		Title     string `json:"title"`
		Objective string `json:"objective"`
		QuerySeed string `json:"query_seed,omitempty"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return
	}
	if body.Title == "" {
		writeError(w, http.StatusBadRequest, "title is required")
		return
	}
	if body.Objective == "" {
		writeError(w, http.StatusBadRequest, "objective is required")
		return
	}

	var querySeeds []string
	if body.QuerySeed != "" {
		querySeeds = []string{body.QuerySeed}
	}

	spec := researchruntime.MissionSpec{
		MissionID:  uuid.NewString(),
		Title:      body.Title,
		Thesis:     body.Objective,
		Mode:       researchruntime.MissionModeOnDemand,
		Class:      researchruntime.MissionClass(body.Type),
		QuerySeeds: querySeeds,
		Trigger: researchruntime.MissionTrigger{
			Type:        researchruntime.MissionTriggerManual,
			TriggeredAt: time.Now().UTC(),
		},
		CreatedAt: time.Now().UTC(),
	}

	if err := r.cfg.Missions.Create(req.Context(), spec); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, spec)
}

// listMissions handles GET /api/research/missions.
// Accepts optional query params: state, class, limit.
func (r *Router) listMissions(w http.ResponseWriter, req *http.Request) {
	q := req.URL.Query()
	filter := store.MissionFilter{}
	if s := q.Get("state"); s != "" {
		filter.State = &s
	}
	if c := q.Get("class"); c != "" {
		filter.Class = &c
	}

	missions, err := r.cfg.Missions.List(req.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if missions == nil {
		missions = []researchruntime.MissionSpec{}
	}
	writeJSON(w, http.StatusOK, missions)
}

// getMission handles GET /api/research/missions/{id}.
func (r *Router) getMission(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	m, err := r.cfg.Missions.Get(req.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "mission not found")
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// cancelMission handles POST /api/research/missions/{id}/cancel.
func (r *Router) cancelMission(w http.ResponseWriter, req *http.Request) {
	id := req.PathValue("id")
	if err := r.cfg.Missions.UpdateState(req.Context(), id, "canceled"); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "canceled"})
}
