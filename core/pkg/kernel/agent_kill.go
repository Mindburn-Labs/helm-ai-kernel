package kernel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AgentKillSwitch provides per-agent termination with receipted audit trail.
// Uses sync.Map for lock-free hot-path reads (IsKilled) and sync.Mutex
// for serialized writes (Kill/Revive), mirroring the FreezeController pattern.
type AgentKillSwitch struct {
	killed   sync.Map // agentID -> *agentKillState
	mu       sync.Mutex
	receipts []AgentKillReceipt
	clock    func() time.Time
}

type agentKillState struct {
	KilledBy  string
	KilledAt  time.Time
	Reason    string
	SagaRunID string // optional: saga that triggered the kill
}

// AgentKillReceipt is a tamper-evident record of a kill/revive action.
type AgentKillReceipt struct {
	Action      string    `json:"action"` // "KILL" or "REVIVE"
	AgentID     string    `json:"agent_id"`
	Principal   string    `json:"principal"` // who issued the command
	Reason      string    `json:"reason,omitempty"`
	SagaRunID   string    `json:"saga_run_id,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	ContentHash string    `json:"content_hash"` // SHA-256 of canonical JSON
}

// NewAgentKillSwitch creates a new per-agent kill switch.
func NewAgentKillSwitch() *AgentKillSwitch {
	return &AgentKillSwitch{
		clock: time.Now,
	}
}

// WithKillSwitchClock injects a deterministic clock for testing.
func (k *AgentKillSwitch) WithKillSwitchClock(clock func() time.Time) *AgentKillSwitch {
	k.clock = clock
	return k
}

// IsKilled returns true if the agent has been killed. Lock-free hot path.
func (k *AgentKillSwitch) IsKilled(agentID string) bool {
	_, killed := k.killed.Load(agentID)
	return killed
}

// Kill terminates an agent. Returns a receipted record.
func (k *AgentKillSwitch) Kill(agentID, principal, reason string) (*AgentKillReceipt, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if _, already := k.killed.Load(agentID); already {
		return nil, fmt.Errorf("agent %s is already killed", agentID)
	}

	now := k.clock()
	state := &agentKillState{
		KilledBy: principal,
		KilledAt: now,
		Reason:   reason,
	}
	k.killed.Store(agentID, state)

	receipt := &AgentKillReceipt{
		Action:    "KILL",
		AgentID:   agentID,
		Principal: principal,
		Reason:    reason,
		Timestamp: now,
	}
	receipt.ContentHash = hashKillReceipt(receipt)
	k.receipts = append(k.receipts, *receipt)
	return receipt, nil
}

// Revive restores a killed agent. Returns a receipted record.
func (k *AgentKillSwitch) Revive(agentID, principal string) (*AgentKillReceipt, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	if _, killed := k.killed.Load(agentID); !killed {
		return nil, fmt.Errorf("agent %s is not killed", agentID)
	}

	k.killed.Delete(agentID)

	now := k.clock()
	receipt := &AgentKillReceipt{
		Action:    "REVIVE",
		AgentID:   agentID,
		Principal: principal,
		Timestamp: now,
	}
	receipt.ContentHash = hashKillReceipt(receipt)
	k.receipts = append(k.receipts, *receipt)
	return receipt, nil
}

// ListKilled returns all currently killed agent IDs.
func (k *AgentKillSwitch) ListKilled() []string {
	var killed []string
	k.killed.Range(func(key, value any) bool {
		killed = append(killed, key.(string))
		return true
	})
	return killed
}

// Receipts returns all kill/revive receipts (for audit).
func (k *AgentKillSwitch) Receipts() []AgentKillReceipt {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]AgentKillReceipt, len(k.receipts))
	copy(out, k.receipts)
	return out
}

// hashKillReceipt computes a deterministic SHA-256 content hash of an AgentKillReceipt.
// Mirrors the FreezeController's hashReceipt pattern: excludes ContentHash from the hash input.
func hashKillReceipt(r *AgentKillReceipt) string {
	canon := struct {
		Action    string `json:"action"`
		AgentID   string `json:"agent_id"`
		Principal string `json:"principal"`
		Reason    string `json:"reason,omitempty"`
		SagaRunID string `json:"saga_run_id,omitempty"`
		Timestamp string `json:"timestamp"`
	}{
		Action:    r.Action,
		AgentID:   r.AgentID,
		Principal: r.Principal,
		Reason:    r.Reason,
		SagaRunID: r.SagaRunID,
		Timestamp: r.Timestamp.UTC().Format(time.RFC3339Nano),
	}
	data, _ := json.Marshal(canon)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
