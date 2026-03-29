package api

import "net/http"

// MountResearchRuntime is a helper for mounting the research runtime API
// into the HELM server's ServeMux.  Call this from RegisterSubsystemRoutes
// (or any server initialisation function) once the research stores and
// services are wired up:
//
//	api.MountResearchRuntime(mux, api.Config{
//	    Missions:    missionStore,
//	    Tasks:       taskStore,
//	    Sources:     sourceStore,
//	    Drafts:      draftStore,
//	    Publications: publicationStore,
//	    Feed:        feedStore,
//	    Overrides:   overrideStore,
//	    Conductor:   conductorService,
//	    Publication: publicationService,
//	})
func MountResearchRuntime(mux *http.ServeMux, cfg Config) {
	r := NewRouter(cfg)
	r.Register(mux)
}
