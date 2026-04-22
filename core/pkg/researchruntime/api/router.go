package api

import (
	"net/http"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/conductor"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/publication"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/researchruntime/store"
)

// Config holds all injectable dependencies for the research API router.
type Config struct {
	Missions     store.MissionStore
	Tasks        store.TaskStore
	Sources      store.SourceStore
	Drafts       store.DraftStore
	Publications store.PublicationStore
	Feed         store.FeedStore
	Overrides    store.OverrideStore
	Conductor    *conductor.Service
	Publication  *publication.Service
}

// Router registers research-runtime HTTP handlers onto a ServeMux.
// It uses Go 1.22+ method+pattern routing (e.g. "GET /api/research/missions/{id}").
type Router struct {
	cfg Config
}

// NewRouter creates a Router from the given Config.
func NewRouter(cfg Config) *Router {
	return &Router{cfg: cfg}
}

// Register mounts all research-runtime routes on mux.
func (r *Router) Register(mux *http.ServeMux) {
	// Missions
	mux.HandleFunc("POST /api/research/missions", r.createMission)
	mux.HandleFunc("GET /api/research/missions", r.listMissions)
	mux.HandleFunc("GET /api/research/missions/{id}", r.getMission)
	mux.HandleFunc("POST /api/research/missions/{id}/cancel", r.cancelMission)

	// Tasks (per-mission)
	mux.HandleFunc("GET /api/research/missions/{id}/tasks", r.listTasks)

	// Sources (per-mission)
	mux.HandleFunc("GET /api/research/missions/{id}/sources", r.listSources)

	// Drafts / artifacts (per-mission)
	mux.HandleFunc("GET /api/research/missions/{id}/drafts", r.listDrafts)

	// Publications
	mux.HandleFunc("GET /api/research/publications", r.listPublications)
	mux.HandleFunc("GET /api/research/publications/{id}", r.getPublication)
	mux.HandleFunc("POST /api/research/publications/{id}/publish", r.publishPublication)

	// Feed
	mux.HandleFunc("GET /api/research/feed", r.getFeed)
	mux.HandleFunc("GET /api/research/feed/stream", r.streamFeed)

	// Overrides
	mux.HandleFunc("GET /api/research/overrides", r.listOverrides)
	mux.HandleFunc("POST /api/research/overrides/{id}/resolve", r.resolveOverride)
}
