// Package api — decision_handler.go serves DecisionRequest CRUD.
//
// Endpoints:
//
//	GET  /api/decisions            — list pending decisions for org
//	POST /api/decisions/:id/resolve — resolve a decision with chosen option
//	POST /api/decisions             — create a new decision (internal use)
package api

import (
	"sync"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// DecisionStore is the interface for persisting DecisionRequests.
// This abstraction allows swapping in-memory for ledger-backed storage.
type DecisionStore interface {
	// List returns all decisions matching the given status filter (empty = all).
	List(orgID string, statusFilter contracts.DecisionRequestStatus) ([]contracts.DecisionRequest, error)

	// Get returns a single decision by ID.
	Get(id string) (*contracts.DecisionRequest, error)

	// Create persists a new DecisionRequest. Returns error if ID already exists.
	Create(dr *contracts.DecisionRequest) error

	// Update persists changes to an existing DecisionRequest.
	Update(dr *contracts.DecisionRequest) error
}

// DecisionHandler serves DecisionRequest API endpoints.
type DecisionHandler struct {
	store DecisionStore
}

// resolveRequest is the payload for POST /api/decisions/:id/resolve.
type resolveRequest struct {
	OptionID         string `json:"option_id"`
	ResolvedBy       string `json:"resolved_by"`
	FreeformResponse string `json:"freeform_response,omitempty"`
}

// ──────────────────────────────────────────────────────────────
// InMemoryDecisionStore — default in-memory implementation
// ──────────────────────────────────────────────────────────────

// InMemoryDecisionStore is a simple in-memory DecisionStore.
// Production deployments should use a ledger-backed store.
type InMemoryDecisionStore struct {
	mu        sync.RWMutex
	decisions map[string]*contracts.DecisionRequest
	order     []string // insertion order
}
