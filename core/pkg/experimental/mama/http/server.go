package http

import (
	"encoding/json"
	"net/http"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/api"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/command"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/experimental/mama/runtime"
)

// Server encapsulates the HTTP REST surface for the MAMA canonical runtime.
type Server struct {
	Registry *command.Registry
	Mission  *runtime.MissionState
}

// NewServer initializes the MAMA HTTP server binding.
func NewServer(reg *command.Registry, mission *runtime.MissionState) *Server {
	return &Server{
		Registry: reg,
		Mission:  mission,
	}
}

// RegisterRoutes binds the MAMA runtime into the unified kernel HTTP multiplexer.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/mama/mission", s.handleMission)
	mux.HandleFunc("/api/mama/mode", s.handleMode)
	mux.HandleFunc("/api/mama/agents", s.handleAgents)
	mux.HandleFunc("/api/mama/health", s.handleHealth)
}

func (s *Server) handleMission(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.WriteMethodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.Mission)
}

func (s *Server) handleMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.WriteMethodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"mode": s.Mission.Mode.CurrentMode,
	})
}

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		api.WriteMethodNotAllowed(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"agents": s.Mission.Agent.ActiveRoles,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ready",
		"engine": "mama-canonical-v1",
	})
}
