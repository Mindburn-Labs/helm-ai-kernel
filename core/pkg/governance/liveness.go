// Package governance provides timeout and liveness management.
// Per HELM Normative Addendum v1.5 Section E - Timeout and Liveness Semantics.
package governance

import (
	"context"
	"sync"
	"time"
)

// LivenessState represents the state of a blocking resource.
type LivenessState string

const (
	LivenessStateActive   LivenessState = "ACTIVE"
	LivenessStatePending  LivenessState = "PENDING"
	LivenessStateExpired  LivenessState = "EXPIRED"
	LivenessStateCanceled LivenessState = "CANCELED"
)

// BlockingStateType categorizes what is being waited on.
type BlockingStateType string

const (
	BlockingStateApproval   BlockingStateType = "APPROVAL"
	BlockingStateObligation BlockingStateType = "OBLIGATION"
	BlockingStateLease      BlockingStateType = "SEQUENCER_LEASE"
	BlockingStateResource   BlockingStateType = "RESOURCE"
)

// DefaultApprovalTimeout is the default timeout for approvals.
// Per Section E.2: Approvals MUST expire.
const DefaultApprovalTimeout = 24 * time.Hour

// DefaultObligationTimeout is the default timeout for obligations.
const DefaultObligationTimeout = 72 * time.Hour

// DefaultLeaseTimeout is the default timeout for sequencer leases.
// Per Section E.4: Sequencer lease management.
const DefaultLeaseTimeout = 30 * time.Second

// BlockingState represents a resource that blocks execution.
// Per Section E.1: Explicit expiry for blocking states.
type BlockingState struct {
	// Identity
	StateID   string            `json:"state_id"`
	StateType BlockingStateType `json:"state_type"`

	// Timing
	CreatedAt time.Time     `json:"created_at"`
	ExpiresAt time.Time     `json:"expires_at"`
	Timeout   time.Duration `json:"timeout_nanos"`

	// Status
	State      LivenessState `json:"state"`
	ResolvedAt *time.Time    `json:"resolved_at,omitempty"`

	// Context
	RequestorID string         `json:"requestor_id,omitempty"`
	ResourceRef string         `json:"resource_ref,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`

	// Callbacks
	onExpire func(*BlockingState)
}

// LivenessManager manages blocking states and enforces timeouts.
// Per Section E.5: Central liveness management.
type LivenessManager struct {
	mu       sync.RWMutex
	states   map[string]*BlockingState
	watchers map[string]context.CancelFunc

	// Default timeouts
	defaultApprovalTimeout   time.Duration
	defaultObligationTimeout time.Duration
	defaultLeaseTimeout      time.Duration
}
