// Package api — decision_handler.go serves DecisionRequest CRUD.
//
// Endpoints:
//
//	GET  /api/decisions            — list pending decisions for org
//	POST /api/decisions/:id/resolve — resolve a decision with chosen option
//	POST /api/decisions             — create a new decision (internal use)
package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

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

// NewDecisionHandler creates a new DecisionHandler.
func NewDecisionHandler(store DecisionStore) *DecisionHandler {
	return &DecisionHandler{store: store}
}

// Register mounts the decision routes on the given mux.
func (h *DecisionHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/api/decisions", h.HandleDecisions)
	mux.HandleFunc("/api/decisions/", h.HandleDecisionByID)
}

// HandleDecisions handles GET (list) and POST (create) on /api/decisions.
func (h *DecisionHandler) HandleDecisions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleList(w, r)
	case http.MethodPost:
		h.handleCreate(w, r)
	default:
		WriteMethodNotAllowed(w)
	}
}

// HandleDecisionByID handles POST /api/decisions/:id/resolve.
func (h *DecisionHandler) HandleDecisionByID(w http.ResponseWriter, r *http.Request) {
	// Parse path: /api/decisions/{id}/resolve
	path := strings.TrimPrefix(r.URL.Path, "/api/decisions/")
	parts := strings.Split(path, "/")

	if len(parts) < 2 || parts[1] != "resolve" {
		WriteNotFound(w, "endpoint not found")
		return
	}

	if r.Method != http.MethodPost {
		WriteMethodNotAllowed(w)
		return
	}

	h.handleResolve(w, r, parts[0])
}

func (h *DecisionHandler) handleList(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		orgID = "default"
	}
	statusFilter := contracts.DecisionRequestStatus(r.URL.Query().Get("status"))

	decisions, err := h.store.List(orgID, statusFilter)
	if err != nil {
		WriteInternal(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"decisions": decisions,
		"count":     len(decisions),
	})
}

func (h *DecisionHandler) handleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit

	var dr contracts.DecisionRequest
	if err := json.NewDecoder(r.Body).Decode(&dr); err != nil {
		WriteBadRequest(w, "invalid request body")
		return
	}

	// Server-side defaults
	if dr.Status == "" {
		dr.Status = contracts.DecisionStatusPending
	}
	if dr.CreatedAt.IsZero() {
		dr.CreatedAt = time.Now().UTC()
	}

	if err := dr.Validate(); err != nil {
		WriteBadRequest(w, err.Error())
		return
	}

	if err := h.store.Create(&dr); err != nil {
		WriteInternal(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(dr)
}

// resolveRequest is the payload for POST /api/decisions/:id/resolve.
type resolveRequest struct {
	OptionID         string `json:"option_id"`
	ResolvedBy       string `json:"resolved_by"`
	FreeformResponse string `json:"freeform_response,omitempty"`
}

func (h *DecisionHandler) handleResolve(w http.ResponseWriter, r *http.Request, id string) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req resolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteBadRequest(w, "invalid request body")
		return
	}

	if req.OptionID == "" {
		WriteBadRequest(w, "option_id is required")
		return
	}
	if req.ResolvedBy == "" {
		WriteBadRequest(w, "resolved_by is required")
		return
	}

	dr, err := h.store.Get(id)
	if err != nil {
		WriteNotFound(w, fmt.Sprintf("decision %q not found", id))
		return
	}

	// Check expiry before resolving
	if dr.CheckExpiry() {
		if err := h.store.Update(dr); err != nil {
			slog.Error("failed to persist expired decision state", "decision_id", id, "error", err)
		}
		WriteBadRequest(w, "decision has expired")
		return
	}

	if err := dr.Resolve(req.OptionID, req.ResolvedBy); err != nil {
		WriteBadRequest(w, err.Error())
		return
	}
	dr.FreeformResponse = req.FreeformResponse

	if err := h.store.Update(dr); err != nil {
		WriteInternal(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(dr)
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

// NewInMemoryDecisionStore creates an empty in-memory store.
func NewInMemoryDecisionStore() *InMemoryDecisionStore {
	return &InMemoryDecisionStore{
		decisions: make(map[string]*contracts.DecisionRequest),
		order:     make([]string, 0),
	}
}

// List returns decisions filtered by org and status.
func (s *InMemoryDecisionStore) List(_ string, statusFilter contracts.DecisionRequestStatus) ([]contracts.DecisionRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]contracts.DecisionRequest, 0, len(s.decisions))
	for _, id := range s.order {
		dr := s.decisions[id]
		if statusFilter == "" || dr.Status == statusFilter {
			result = append(result, *dr)
		}
	}
	return result, nil
}

// Get returns a decision by ID.
func (s *InMemoryDecisionStore) Get(id string) (*contracts.DecisionRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dr, ok := s.decisions[id]
	if !ok {
		return nil, fmt.Errorf("decision %q not found", id)
	}
	// Return a copy to avoid concurrent mutation
	copy := *dr
	return &copy, nil
}

// Create adds a new decision to the store.
func (s *InMemoryDecisionStore) Create(dr *contracts.DecisionRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.decisions[dr.RequestID]; exists {
		return fmt.Errorf("decision %q already exists", dr.RequestID)
	}

	stored := *dr
	s.decisions[dr.RequestID] = &stored
	s.order = append(s.order, dr.RequestID)
	return nil
}

// Update replaces an existing decision in the store.
func (s *InMemoryDecisionStore) Update(dr *contracts.DecisionRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.decisions[dr.RequestID]; !exists {
		return fmt.Errorf("decision %q not found", dr.RequestID)
	}

	stored := *dr
	s.decisions[dr.RequestID] = &stored
	return nil
}
