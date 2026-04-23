// Package api — autonomy_handler.go serves the GlobalAutonomyState projection.
//
// GET /api/autonomy/state
//
// This handler computes GlobalAutonomyState on each request by reading from
// authoritative stores. It does NOT cache — the caller rate-limits via polling
// interval or subscribes via WebSocket for push.
package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// AutonomyStateProvider is the interface for computing the current autonomy state.
// Implementors should read from authoritative stores (ledger, event store, etc.)
// and return a derived projection.
type AutonomyStateProvider interface {
	// ComputeState derives the current GlobalAutonomyState from truth stores.
	ComputeState(orgID string) (*contracts.GlobalAutonomyState, error)
}

// AutonomyControlProvider extends AutonomyStateProvider with mutation capabilities.
// This allows the control endpoint to change the global mode.
type AutonomyControlProvider interface {
	AutonomyStateProvider

	// SetGlobalMode transitions the org to a new global mode.
	SetGlobalMode(mode contracts.GlobalMode)

	// GetCurrentPosture returns the current posture for policy validation.
	GetCurrentPosture() contracts.Posture

	// GetCurrentGlobalMode returns the current global mode.
	GetCurrentGlobalMode() contracts.GlobalMode
}

// AutonomyHandler serves autonomy-related API endpoints.
type AutonomyHandler struct {
	provider        AutonomyStateProvider
	controlProvider AutonomyControlProvider // nil if control is not supported
}

// NewAutonomyHandler creates a new AutonomyHandler.
func NewAutonomyHandler(provider AutonomyStateProvider) *AutonomyHandler {
	ctrl, _ := provider.(AutonomyControlProvider)
	return &AutonomyHandler{provider: provider, controlProvider: ctrl}
}

// Register mounts the autonomy routes on the given mux.
// The control endpoint requires admin auth (H-2: fail-closed if HELM_ADMIN_API_KEY unset).
// State endpoint is read-only and does not require auth.
func (h *AutonomyHandler) Register(mux *http.ServeMux, adminAuth func(http.Handler) http.Handler) {
	mux.HandleFunc("/api/autonomy/state", h.HandleGetState)
	if adminAuth != nil {
		mux.Handle("/api/autonomy/control", adminAuth(http.HandlerFunc(h.HandleControl)))
	} else {
		mux.HandleFunc("/api/autonomy/control", h.HandleControl)
	}
}

// ──────────────────────────────────────────────────────────────
// Control actions
// ──────────────────────────────────────────────────────────────

// controlRequest is the JSON body for POST /api/autonomy/control.
type controlRequest struct {
	Action string `json:"action"` // PAUSE, RUN, FREEZE, ISLAND
}

// controlResponse is the JSON response from the control endpoint.
type controlResponse struct {
	PreviousMode string `json:"previous_mode"`
	NewMode      string `json:"new_mode"`
}

// validControlActions maps action strings to their target GlobalMode.
var validControlActions = map[string]contracts.GlobalMode{
	"PAUSE":  contracts.GlobalModePaused,
	"RUN":    contracts.GlobalModeRunning,
	"FREEZE": contracts.GlobalModeFrozen,
	"ISLAND": contracts.GlobalModeIslanded,
}

// actionsRequiringSovereign are actions that need Sovereign or Transact posture.
var actionsRequiringSovereign = map[string]bool{
	"FREEZE": true,
	"ISLAND": true,
}

// HandleControl serves POST /api/autonomy/control.
// Accepts {"action": "PAUSE|RUN|FREEZE|ISLAND"} and applies the mode transition.
func (h *AutonomyHandler) HandleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		WriteMethodNotAllowed(w)
		return
	}

	if h.controlProvider == nil {
		WriteBadRequest(w, "control operations not supported by this provider")
		return
	}

	var req controlRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteBadRequest(w, "invalid JSON body")
		return
	}

	targetMode, ok := validControlActions[req.Action]
	if !ok {
		WriteBadRequest(w, "invalid action: must be one of PAUSE, RUN, FREEZE, ISLAND")
		return
	}

	// Validate posture permissions
	currentPosture := h.controlProvider.GetCurrentPosture()
	if actionsRequiringSovereign[req.Action] {
		if currentPosture != contracts.PostureSovereign && currentPosture != contracts.PostureTransact {
			WriteForbidden(w, req.Action+" requires TRANSACT or SOVEREIGN posture")
			return
		}
	}

	// No-op if already in target mode
	currentMode := h.controlProvider.GetCurrentGlobalMode()
	if currentMode == targetMode {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlResponse{
			PreviousMode: string(currentMode),
			NewMode:      string(targetMode),
		})
		return
	}

	h.controlProvider.SetGlobalMode(targetMode)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(controlResponse{
		PreviousMode: string(currentMode),
		NewMode:      string(targetMode),
	})
}

// HandleGetState serves GET /api/autonomy/state.
// Returns the current GlobalAutonomyState projection for the authenticated org.
func (h *AutonomyHandler) HandleGetState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		WriteMethodNotAllowed(w)
		return
	}

	// NOTE: orgID is extracted from query param; production deployments
	// should inject from authenticated session via middleware.
	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		orgID = "default"
	}

	state, err := h.provider.ComputeState(orgID)
	if err != nil {
		WriteInternal(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	_ = json.NewEncoder(w).Encode(state)
}

// ──────────────────────────────────────────────────────────────
// InMemoryAutonomyProvider — default implementation
// ──────────────────────────────────────────────────────────────

// InMemoryAutonomyProvider is a simple in-memory implementation of AutonomyStateProvider.
// It holds the current state and provides methods to update it.
// Production deployments should replace this with a ledger-backed implementation.
type InMemoryAutonomyProvider struct {
	posture    contracts.Posture
	globalMode contracts.GlobalMode
	decisions  []contracts.DecisionRequest
	runs       []contracts.RunSummaryProjection
}

// NewInMemoryAutonomyProvider creates a provider with defaults.
func NewInMemoryAutonomyProvider() *InMemoryAutonomyProvider {
	return &InMemoryAutonomyProvider{
		posture:    contracts.PostureObserve,
		globalMode: contracts.GlobalModeRunning,
		decisions:  make([]contracts.DecisionRequest, 0),
		runs:       make([]contracts.RunSummaryProjection, 0),
	}
}

// ComputeState derives GlobalAutonomyState from the in-memory state.
func (p *InMemoryAutonomyProvider) ComputeState(orgID string) (*contracts.GlobalAutonomyState, error) {
	// Compute NowNextNeed from active runs and blockers
	summary := p.computeSummary()

	// Compute risk level from anomalies and blocked runs
	risk := p.computeRiskLevel()

	// Count blockers
	pendingBlockers := make([]contracts.DecisionRequest, 0, len(p.decisions))
	for _, d := range p.decisions {
		if d.Status == contracts.DecisionStatusPending {
			pendingBlockers = append(pendingBlockers, d)
		}
	}

	state := &contracts.GlobalAutonomyState{
		OrgID:          orgID,
		Posture:        p.posture,
		GlobalMode:     p.globalMode,
		SchedulerState: contracts.SchedulerAwake,
		Summary:        summary,
		ActiveRuns:     p.runs,
		BlockersQueue:  pendingBlockers,
		RiskLevel:      risk,
		Anomalies:      make([]contracts.Anomaly, 0),
		ComputedAt:     time.Now().UTC(),
	}

	return state, nil
}

// AddDecisionRequest adds a decision to the blocker queue.
func (p *InMemoryAutonomyProvider) AddDecisionRequest(dr contracts.DecisionRequest) {
	p.decisions = append(p.decisions, dr)
}

// AddRun adds a run summary to the active runs.
func (p *InMemoryAutonomyProvider) AddRun(run contracts.RunSummaryProjection) {
	p.runs = append(p.runs, run)
}

// SetPosture updates the current posture.
func (p *InMemoryAutonomyProvider) SetPosture(posture contracts.Posture) {
	p.posture = posture
}

// SetGlobalMode updates the global mode.
func (p *InMemoryAutonomyProvider) SetGlobalMode(mode contracts.GlobalMode) {
	p.globalMode = mode
}

// GetCurrentPosture returns the current posture.
func (p *InMemoryAutonomyProvider) GetCurrentPosture() contracts.Posture {
	return p.posture
}

// GetCurrentGlobalMode returns the current global mode.
func (p *InMemoryAutonomyProvider) GetCurrentGlobalMode() contracts.GlobalMode {
	return p.globalMode
}

func (p *InMemoryAutonomyProvider) computeSummary() contracts.NowNextNeed {
	var now, next, needYou string

	// Now: most recent active run
	for _, r := range p.runs {
		if r.Status == "active" {
			now = r.NextAction
			break
		}
	}
	if now == "" {
		now = "Idle — no active runs"
	}

	// Next: first queued run
	for _, r := range p.runs {
		if r.Status == "pending" {
			next = r.NextAction
			break
		}
	}
	if next == "" {
		next = "Nothing scheduled"
	}

	// NeedYou: first pending decision
	for _, d := range p.decisions {
		if d.Status == contracts.DecisionStatusPending {
			needYou = d.Title
			break
		}
	}

	return contracts.NowNextNeed{
		Now:     now,
		Next:    next,
		NeedYou: needYou,
	}
}

func (p *InMemoryAutonomyProvider) computeRiskLevel() contracts.RiskLevel {
	blockedCount := 0
	for _, d := range p.decisions {
		if d.Status == contracts.DecisionStatusPending {
			blockedCount++
		}
	}
	for _, r := range p.runs {
		if r.CurrentStage == contracts.RunStageBlocked {
			blockedCount++
		}
	}

	switch {
	case blockedCount >= 5:
		return contracts.RiskLevelCritical
	case blockedCount >= 3:
		return contracts.RiskLevelHigh
	case blockedCount >= 1:
		return contracts.RiskLevelElevated
	default:
		return contracts.RiskLevelNormal
	}
}
