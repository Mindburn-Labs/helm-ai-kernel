// Package governance provides timeout and liveness management.
// Per HELM Normative Addendum v1.5 Section E - Timeout and Liveness Semantics.
package governance

import (
	"context"
	"fmt"
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

// NewBlockingState creates a new blocking state.
func NewBlockingState(stateID string, stateType BlockingStateType, timeout time.Duration) *BlockingState {
	now := time.Now().UTC()
	return &BlockingState{
		StateID:   stateID,
		StateType: stateType,
		CreatedAt: now,
		ExpiresAt: now.Add(timeout),
		Timeout:   timeout,
		State:     LivenessStatePending,
		Metadata:  make(map[string]any),
	}
}

// NewApprovalState creates a blocking state for an approval.
func NewApprovalState(approvalID string, timeout time.Duration) *BlockingState {
	if timeout == 0 {
		timeout = DefaultApprovalTimeout
	}
	return NewBlockingState(approvalID, BlockingStateApproval, timeout)
}

// NewObligationState creates a blocking state for an obligation.
func NewObligationState(obligationID string, timeout time.Duration) *BlockingState {
	if timeout == 0 {
		timeout = DefaultObligationTimeout
	}
	return NewBlockingState(obligationID, BlockingStateObligation, timeout)
}

// NewSequencerLease creates a blocking state for a sequencer lease.
func NewSequencerLease(leaseID string, timeout time.Duration) *BlockingState {
	if timeout == 0 {
		timeout = DefaultLeaseTimeout
	}
	return NewBlockingState(leaseID, BlockingStateLease, timeout)
}

// IsExpired checks if the blocking state has expired.
func (bs *BlockingState) IsExpired() bool {
	return time.Now().UTC().After(bs.ExpiresAt)
}

// TimeRemaining returns the duration until expiry.
func (bs *BlockingState) TimeRemaining() time.Duration {
	remaining := time.Until(bs.ExpiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Resolve marks the blocking state as resolved.
func (bs *BlockingState) Resolve() {
	now := time.Now().UTC()
	bs.ResolvedAt = &now
	bs.State = LivenessStateActive
}

// Cancel marks the blocking state as canceled.
func (bs *BlockingState) Cancel() {
	now := time.Now().UTC()
	bs.ResolvedAt = &now
	bs.State = LivenessStateCanceled
}

// Expire marks the blocking state as expired.
func (bs *BlockingState) Expire() {
	bs.State = LivenessStateExpired
	if bs.onExpire != nil {
		bs.onExpire(bs)
	}
}

// Extend extends the expiry time.
func (bs *BlockingState) Extend(extension time.Duration) error {
	if bs.State != LivenessStatePending {
		return fmt.Errorf("liveness: cannot extend state in %s status", bs.State)
	}
	bs.ExpiresAt = time.Now().UTC().Add(extension)
	return nil
}

// OnExpire registers an expiry callback.
func (bs *BlockingState) OnExpire(callback func(*BlockingState)) {
	bs.onExpire = callback
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

// NewLivenessManager creates a new liveness manager.
func NewLivenessManager() *LivenessManager {
	return &LivenessManager{
		states:                   make(map[string]*BlockingState),
		watchers:                 make(map[string]context.CancelFunc),
		defaultApprovalTimeout:   DefaultApprovalTimeout,
		defaultObligationTimeout: DefaultObligationTimeout,
		defaultLeaseTimeout:      DefaultLeaseTimeout,
	}
}

// Register adds a blocking state and starts monitoring.
func (lm *LivenessManager) Register(bs *BlockingState) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	if _, exists := lm.states[bs.StateID]; exists {
		return fmt.Errorf("liveness: state %s already registered", bs.StateID)
	}

	lm.states[bs.StateID] = bs

	// Start timeout watcher
	ctx, cancel := context.WithCancel(context.Background())
	lm.watchers[bs.StateID] = cancel

	go lm.watchExpiry(ctx, bs)

	return nil
}

// watchExpiry monitors a blocking state for expiry.
func (lm *LivenessManager) watchExpiry(ctx context.Context, bs *BlockingState) {
	timer := time.NewTimer(bs.TimeRemaining())
	defer timer.Stop()

	select {
	case <-ctx.Done():
		// Canceled or resolved
		return
	case <-timer.C:
		lm.mu.Lock()
		if bs.State == LivenessStatePending {
			bs.Expire()
		}
		lm.mu.Unlock()
	}
}

// Get retrieves a blocking state by ID.
func (lm *LivenessManager) Get(stateID string) (*BlockingState, error) {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	bs, exists := lm.states[stateID]
	if !exists {
		return nil, fmt.Errorf("liveness: state %s not found", stateID)
	}

	return bs, nil
}

// Resolve marks a blocking state as resolved.
func (lm *LivenessManager) Resolve(stateID string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	bs, exists := lm.states[stateID]
	if !exists {
		return fmt.Errorf("liveness: state %s not found", stateID)
	}

	if bs.IsExpired() {
		return fmt.Errorf("liveness: state %s has already expired", stateID)
	}

	bs.Resolve()

	// Cancel the watcher
	if cancel, ok := lm.watchers[stateID]; ok {
		cancel()
		delete(lm.watchers, stateID)
	}

	return nil
}

// Cancel cancels a blocking state.
func (lm *LivenessManager) Cancel(stateID string) error {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	bs, exists := lm.states[stateID]
	if !exists {
		return fmt.Errorf("liveness: state %s not found", stateID)
	}

	bs.Cancel()

	// Cancel the watcher
	if cancel, ok := lm.watchers[stateID]; ok {
		cancel()
		delete(lm.watchers, stateID)
	}

	return nil
}

// CleanupExpired removes expired states.
func (lm *LivenessManager) CleanupExpired() int {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	count := 0
	for id, bs := range lm.states {
		if bs.State == LivenessStateExpired {
			if cancel, ok := lm.watchers[id]; ok {
				cancel()
				delete(lm.watchers, id)
			}
			delete(lm.states, id)
			count++
		}
	}

	return count
}

// ActiveCount returns the number of active/pending states.
func (lm *LivenessManager) ActiveCount() int {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	count := 0
	for _, bs := range lm.states {
		if bs.State == LivenessStatePending || bs.State == LivenessStateActive {
			count++
		}
	}
	return count
}

// PendingApprovals returns all pending approval states.
func (lm *LivenessManager) PendingApprovals() []*BlockingState {
	lm.mu.RLock()
	defer lm.mu.RUnlock()

	result := make([]*BlockingState, 0)
	for _, bs := range lm.states {
		if bs.StateType == BlockingStateApproval && bs.State == LivenessStatePending {
			result = append(result, bs)
		}
	}
	return result
}

// Shutdown stops all watchers.
func (lm *LivenessManager) Shutdown() {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	for id, cancel := range lm.watchers {
		cancel()
		delete(lm.watchers, id)
	}
}
