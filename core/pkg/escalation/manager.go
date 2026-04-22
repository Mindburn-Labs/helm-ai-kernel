// Package escalation provides the Escalation Manager — the runtime engine
// that handles human-in-the-loop judgment for acts classified as JUDGMENT_REQUIRED.
//
// The manager creates EscalationIntents, tracks their lifecycle,
// handles timeouts, and produces immutable EscalationReceipts.
package escalation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

// Manager handles the lifecycle of escalation intents.
type Manager struct {
	mu      sync.Mutex
	intents map[string]*contracts.EscalationIntent
	clock   func() time.Time
}

// NewManager creates a new escalation manager.
func NewManager() *Manager {
	return &Manager{
		intents: make(map[string]*contracts.EscalationIntent),
		clock:   time.Now,
	}
}

// WithClock overrides the clock for deterministic testing.
func (m *Manager) WithClock(clock func() time.Time) *Manager {
	m.clock = clock
	return m
}

// CreateIntent creates a new escalation intent from a judgment decision.
// This is called when the Judgment Classifier returns JUDGMENT_REQUIRED.
func (m *Manager) CreateIntent(
	ctx context.Context,
	decision *contracts.JudgmentDecision,
	heldEffect contracts.HeldEffect,
	escalationCtx contracts.EscalationContext,
	runID, envelopeID string,
) (*contracts.EscalationIntent, error) {
	_ = ctx
	now := m.clock()

	// Determine approval spec from escalation template
	approval := contracts.ApprovalSpec{
		ApproverRoles:  []string{"operator"},
		Quorum:         1,
		TimeoutSeconds: 300,
		OnTimeout:      "deny",
	}
	if decision.EscalationTemplate != nil {
		t := decision.EscalationTemplate
		if len(t.ApproverRoles) > 0 {
			approval.ApproverRoles = t.ApproverRoles
		}
		if t.Quorum > 0 {
			approval.Quorum = t.Quorum
		}
		if t.TimeoutSeconds > 0 {
			approval.TimeoutSeconds = t.TimeoutSeconds
		}
		if t.OnTimeout != "" {
			approval.OnTimeout = t.OnTimeout
		}
	}

	intent := &contracts.EscalationIntent{
		IntentID:    uuid.New().String(),
		RunID:       runID,
		EnvelopeID:  envelopeID,
		TriggerRule: decision.MatchedRule,
		Verdict:     decision.Verdict,
		HeldEffect:  heldEffect,
		Context:     escalationCtx,
		Approval:    approval,
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Duration(approval.TimeoutSeconds) * time.Second),
		Status:      contracts.EscalationStatusPending,
	}

	m.mu.Lock()
	m.intents[intent.IntentID] = intent
	m.mu.Unlock()

	return intent, nil
}

// Approve approves an escalation intent.
func (m *Manager) Approve(ctx context.Context, intentID string, approverID string) (*contracts.EscalationReceipt, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()

	intent, ok := m.intents[intentID]
	if !ok {
		return nil, fmt.Errorf("escalation intent %q not found", intentID)
	}

	if intent.Status != contracts.EscalationStatusPending {
		return nil, fmt.Errorf("escalation intent %q is not PENDING (status=%s)", intentID, intent.Status)
	}

	// Check expiry
	now := m.clock()
	if now.After(intent.ExpiresAt) {
		intent.Status = contracts.EscalationStatusTimedOut
		return m.createReceipt(intent, now), nil
	}

	intent.Status = contracts.EscalationStatusApproved
	receipt := m.createReceipt(intent, now)
	receipt.ApprovedBy = []string{approverID}

	return receipt, nil
}

// Deny denies an escalation intent.
func (m *Manager) Deny(ctx context.Context, intentID, denierID, reason string) (*contracts.EscalationReceipt, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()

	intent, ok := m.intents[intentID]
	if !ok {
		return nil, fmt.Errorf("escalation intent %q not found", intentID)
	}

	if intent.Status != contracts.EscalationStatusPending {
		return nil, fmt.Errorf("escalation intent %q is not PENDING (status=%s)", intentID, intent.Status)
	}

	intent.Status = contracts.EscalationStatusDenied
	receipt := m.createReceipt(intent, m.clock())
	receipt.DeniedBy = denierID
	receipt.DenyReason = reason

	return receipt, nil
}

// CheckTimeouts scans pending intents and handles any that have expired.
// Returns receipts for any timed-out intents.
func (m *Manager) CheckTimeouts(ctx context.Context) ([]*contracts.EscalationReceipt, error) {
	_ = ctx
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()
	var receipts []*contracts.EscalationReceipt

	for _, intent := range m.intents {
		if intent.Status != contracts.EscalationStatusPending {
			continue
		}
		if now.After(intent.ExpiresAt) {
			intent.Status = contracts.EscalationStatusTimedOut
			receipts = append(receipts, m.createReceipt(intent, now))
		}
	}

	return receipts, nil
}

// GetIntent returns a pending escalation intent by ID.
func (m *Manager) GetIntent(intentID string) (*contracts.EscalationIntent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	intent, ok := m.intents[intentID]
	if !ok {
		return nil, fmt.Errorf("escalation intent %q not found", intentID)
	}
	return intent, nil
}

// PendingCount returns the number of pending escalations.
func (m *Manager) PendingCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()

	count := 0
	for _, intent := range m.intents {
		if intent.Status == contracts.EscalationStatusPending {
			count++
		}
	}
	return count
}

func (m *Manager) createReceipt(intent *contracts.EscalationIntent, resolvedAt time.Time) *contracts.EscalationReceipt {
	durationMs := resolvedAt.Sub(intent.CreatedAt).Milliseconds()

	receipt := &contracts.EscalationReceipt{
		ReceiptID:  uuid.New().String(),
		IntentID:   intent.IntentID,
		Outcome:    intent.Status,
		ResolvedAt: resolvedAt,
		DurationMs: durationMs,
	}

	// Compute content hash for audit
	hashable := struct {
		IntentID string                     `json:"intent_id"`
		Outcome  contracts.EscalationStatus `json:"outcome"`
	}{
		IntentID: intent.IntentID,
		Outcome:  intent.Status,
	}
	data, _ := json.Marshal(hashable)
	h := sha256.Sum256(data)
	receipt.ContentHash = "sha256:" + hex.EncodeToString(h[:])

	return receipt
}
