// Package api — autonomy_handler.go serves the GlobalAutonomyState projection.
//
// GET /api/autonomy/state
//
// This handler computes GlobalAutonomyState on each request by reading from
// authoritative stores. It does NOT cache — the caller rate-limits via polling
// interval or subscribes via WebSocket for push.
package api

import (
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
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
