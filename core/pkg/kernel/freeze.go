package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// FreezeController implements a global kill-switch for all enforcement decisions.
//
// When frozen, the Guardian MUST deny all incoming requests with reason code
// SYSTEM_FROZEN. The freeze state is stored as an atomic boolean for lock-free
// reads on the hot path. All transitions (freeze/unfreeze) emit a FreezeReceipt
// with cryptographic content hash for the audit trail.
//
// Design invariants:
//   - Read path (IsFrozen) is lock-free via atomic.Bool
//   - Write path (Freeze/Unfreeze) is serialized via mutex
//   - All transitions are receipted and timestamped
//   - Clock is injected for deterministic testing
type FreezeController struct {
	frozen atomic.Bool

	mu       sync.Mutex
	frozenBy string
	frozenAt time.Time
	receipts []FreezeReceipt
	clock    func() time.Time
}

// FreezeReceipt is the audit record for a freeze/unfreeze transition.
type FreezeReceipt struct {
	Action      string    `json:"action"`       // "freeze" or "unfreeze"
	Principal   string    `json:"principal"`    // who performed the action
	Timestamp   time.Time `json:"timestamp"`    // when the action occurred
	ContentHash string    `json:"content_hash"` // SHA-256 of the canonical receipt
}

// NewFreezeController creates a new FreezeController with the system clock.
func NewFreezeController() *FreezeController {
	return &FreezeController{
		clock: time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (fc *FreezeController) WithClock(clock func() time.Time) *FreezeController {
	fc.clock = clock
	return fc
}

// IsFrozen returns whether the system is currently in a global freeze state.
// This is the hot-path check used by the Guardian before any policy evaluation.
// It is lock-free for maximum throughput.
func (fc *FreezeController) IsFrozen() bool {
	return fc.frozen.Load()
}

// FreezeState returns the current freeze state details.
// Returns (isFrozen, principal, timestamp).
func (fc *FreezeController) FreezeState() (bool, string, time.Time) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	return fc.frozen.Load(), fc.frozenBy, fc.frozenAt
}

// Freeze activates the global freeze. All subsequent enforcement decisions
// will be denied with SYSTEM_FROZEN until Unfreeze is called.
//
// Returns a FreezeReceipt for the audit trail. Returns an error if already frozen.
func (fc *FreezeController) Freeze(principal string) (*FreezeReceipt, error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if fc.frozen.Load() {
		return nil, fmt.Errorf("system already frozen by %s at %s", fc.frozenBy, fc.frozenAt.Format(time.RFC3339))
	}

	now := fc.clock()
	fc.frozen.Store(true)
	fc.frozenBy = principal
	fc.frozenAt = now

	receipt := &FreezeReceipt{
		Action:    "freeze",
		Principal: principal,
		Timestamp: now,
	}
	receipt.ContentHash = hashReceipt(receipt)
	fc.receipts = append(fc.receipts, *receipt)

	return receipt, nil
}

// Unfreeze deactivates the global freeze, allowing enforcement decisions
// to proceed normally.
//
// Returns a FreezeReceipt for the audit trail. Returns an error if not frozen.
func (fc *FreezeController) Unfreeze(principal string) (*FreezeReceipt, error) {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	if !fc.frozen.Load() {
		return nil, fmt.Errorf("system is not frozen")
	}

	now := fc.clock()
	fc.frozen.Store(false)

	receipt := &FreezeReceipt{
		Action:    "unfreeze",
		Principal: principal,
		Timestamp: now,
	}
	receipt.ContentHash = hashReceipt(receipt)
	fc.receipts = append(fc.receipts, *receipt)

	// Clear freeze metadata
	fc.frozenBy = ""
	fc.frozenAt = time.Time{}

	return receipt, nil
}

// Receipts returns all freeze/unfreeze transition receipts.
func (fc *FreezeController) Receipts() []FreezeReceipt {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	out := make([]FreezeReceipt, len(fc.receipts))
	copy(out, fc.receipts)
	return out
}

// hashReceipt computes a deterministic SHA-256 content hash of a FreezeReceipt.
func hashReceipt(r *FreezeReceipt) string {
	// Use a copy without the hash field for canonical hashing
	canon := struct {
		Action    string `json:"action"`
		Principal string `json:"principal"`
		Timestamp string `json:"timestamp"`
	}{
		Action:    r.Action,
		Principal: r.Principal,
		Timestamp: r.Timestamp.UTC().Format(time.RFC3339Nano),
	}
	data, _ := json.Marshal(canon)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
