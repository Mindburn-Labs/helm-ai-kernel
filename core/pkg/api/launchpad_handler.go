package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/plan"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/readmodel"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/registry"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/repair"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/secrets"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/launchpad/session"
)

type launchpadPlanRequest struct {
	AppID       string `json:"app_id"`
	SubstrateID string `json:"substrate_id"`
	Principal   string `json:"principal"`
}

func (s *Server) handleLaunchpad(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.requireAuthenticated(w, r)
	if !ok {
		return
	}
	r = r.WithContext(WithAuthenticatedPrincipal(r.Context(), principal))

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/launchpad/")
	catalog, err := registry.LoadCatalog("")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if err := catalog.Validate(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	switch {
	case path == "apps" && r.Method == http.MethodGet:
		secretStatuses, _ := secrets.NewStore("").Statuses()
		runs, _ := session.NewStore("").List()
		writeJSON(w, http.StatusOK, map[string]any{"apps": readmodel.RegistryApps(catalog, secretStatuses, runs)})
	case path == "substrates" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"substrates": catalog.Substrates})
	case path == "matrix" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"matrix": catalog.Matrix()})
	case path == "plan" && r.Method == http.MethodPost:
		s.handleLaunchpadPlan(w, r, catalog)
	case path == "launch" && r.Method == http.MethodPost:
		s.handleLaunchpadLaunch(w, r, catalog)
	case strings.HasPrefix(path, "launches/"):
		s.handleLaunchpadRunPath(w, r, strings.TrimPrefix(path, "launches/"))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleLaunchpadPlan(w http.ResponseWriter, r *http.Request, catalog *registry.Catalog) {
	req, ok := decodeLaunchpadPlanRequest(w, r)
	if !ok {
		return
	}
	compiled, err := compileLaunchpadPlan(catalog, req)
	if err != nil {
		compiled.ReasonCode = coalesce(compiled.ReasonCode, err.Error())
	}
	writeJSON(w, http.StatusAccepted, compiled)
}

func (s *Server) handleLaunchpadLaunch(w http.ResponseWriter, r *http.Request, catalog *registry.Catalog) {
	req, ok := decodeLaunchpadPlanRequest(w, r)
	if !ok {
		return
	}
	compiled, err := compileLaunchpadPlan(catalog, req)
	if err != nil {
		compiled.ReasonCode = coalesce(compiled.ReasonCode, err.Error())
	}
	run, saveErr := session.NewExecutor(session.NewStore("")).ExecuteLaunch(compiled, session.ExecuteOptions{Reason: "launch requested through OSS Console API"})
	if saveErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": saveErr.Error()})
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) handleLaunchpadRunPath(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "launch id required", http.StatusBadRequest)
		return
	}
	launchID := parts[0]
	store := session.NewStore("")
	if len(parts) == 1 && r.Method == http.MethodGet {
		run, err := store.Get(launchID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, run)
		return
	}
	if len(parts) == 2 && parts[1] == "repair" && r.Method == http.MethodPost {
		run, err := store.Get(launchID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		diagnostics := []repair.Diagnostic{{Code: "ERR_REPAIR_REQUIRES_OPERATOR_APPROVAL", Message: "repair is deterministic planning only until operator approval is recorded"}}
		if run.State == session.StateEscalated {
			diagnostics = append(diagnostics, repair.Diagnostic{Code: "ERR_LAUNCH_ESCALATED", Message: run.Reason})
		}
		writeJSON(w, http.StatusAccepted, repair.EscalatedPlan(launchID, diagnostics))
		return
	}
	if len(parts) == 2 && parts[1] == "delete" && r.Method == http.MethodPost {
		run, err := store.Get(launchID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		_ = run
		deleted, err := session.NewExecutor(store).DeleteLaunch(launchID, true)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, deleted)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func decodeLaunchpadPlanRequest(w http.ResponseWriter, r *http.Request) (launchpadPlanRequest, bool) {
	var req launchpadPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid launchpad request"})
		return req, false
	}
	if req.Principal == "" {
		req.Principal = "console"
	}
	if principal, ok := AuthenticatedPrincipalFromContext(r.Context()); ok {
		req.Principal = principal.ID
	}
	return req, true
}

func compileLaunchpadPlan(catalog *registry.Catalog, req launchpadPlanRequest) (plan.LaunchPlan, error) {
	app, ok := catalog.App(req.AppID)
	if !ok {
		return plan.FailurePlan(req.AppID, req.SubstrateID, req.Principal, "DENY", "DENIED", "ERR_LAUNCHPAD_UNKNOWN_APP"), fmt.Errorf("unknown app: %s", req.AppID)
	}
	substrate, ok := catalog.Substrate(req.SubstrateID)
	if !ok {
		return plan.FailurePlan(req.AppID, req.SubstrateID, req.Principal, "DENY", "DENIED", "ERR_LAUNCHPAD_UNKNOWN_SUBSTRATE"), fmt.Errorf("unknown substrate: %s", req.SubstrateID)
	}
	return plan.CompileWithRoot(app, substrate, req.Principal, catalog.Root)
}

func coalesce(left, right string) string {
	if left != "" {
		return left
	}
	return right
}
