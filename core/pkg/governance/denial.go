// Package governance — DenialReceipt.
//
// Per HELM 2030 Spec §1.2 — Fail-Closed Autonomy:
//
//	If policy, provenance, tool boundaries, tenancy isolation, jurisdiction
//	constraints, verification, or budgets cannot be satisfied, HELM refuses
//	the action and emits a DenialReceipt. No "best effort" in production paths.
package governance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// DenialReason categorizes why an action was denied.
type DenialReason string

const (
	DenialPolicy       DenialReason = "POLICY"
	DenialProvenance   DenialReason = "PROVENANCE"
	DenialBudget       DenialReason = "BUDGET"
	DenialSandbox      DenialReason = "SANDBOX"
	DenialTenant       DenialReason = "TENANT"
	DenialJurisdiction DenialReason = "JURISDICTION"
	DenialVerification DenialReason = "VERIFICATION"
	DenialEnvelope     DenialReason = "ENVELOPE"
)

// DenialReceipt is the proof artifact emitted when any fail-closed boundary
// refuses an action. Every refusal is receipted — no silent drops.
type DenialReceipt struct {
	ReceiptID   string       `json:"receipt_id"`
	DeniedAt    time.Time    `json:"denied_at"`
	Principal   string       `json:"principal"`
	TenantID    string       `json:"tenant_id,omitempty"`
	Action      string       `json:"action"`
	Reason      DenialReason `json:"reason"`
	Details     string       `json:"details"`
	PolicyRef   string       `json:"policy_ref,omitempty"`
	EnvelopeRef string       `json:"envelope_ref,omitempty"`
	RunID       string       `json:"run_id,omitempty"`
	ContentHash string       `json:"content_hash"`
}

// DenialLedger records all denial receipts for audit.
type DenialLedger struct {
	mu       sync.Mutex
	receipts []DenialReceipt
	seq      int64
	clock    func() time.Time
}

// NewDenialLedger creates a new ledger.
func NewDenialLedger() *DenialLedger {
	return &DenialLedger{
		receipts: make([]DenialReceipt, 0),
		clock:    time.Now,
	}
}

// WithClock overrides clock for testing.
func (l *DenialLedger) WithClock(clock func() time.Time) *DenialLedger {
	l.clock = clock
	return l
}

// Deny records a denial and returns the receipt.
func (l *DenialLedger) Deny(principal, action string, reason DenialReason, details string) *DenialReceipt {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	now := l.clock()
	receiptID := fmt.Sprintf("denial-%d", l.seq)

	hashInput := fmt.Sprintf("%s:%s:%s:%s:%s", receiptID, principal, action, reason, details)
	h := sha256.Sum256([]byte(hashInput))

	receipt := DenialReceipt{
		ReceiptID:   receiptID,
		DeniedAt:    now,
		Principal:   principal,
		Action:      action,
		Reason:      reason,
		Details:     details,
		ContentHash: "sha256:" + hex.EncodeToString(h[:]),
	}

	l.receipts = append(l.receipts, receipt)
	return &receipt
}

// DenyWithContext records a denial with full context.
func (l *DenialLedger) DenyWithContext(principal, tenantID, action, runID string, reason DenialReason, details, policyRef, envelopeRef string) *DenialReceipt {
	receipt := l.Deny(principal, action, reason, details)

	l.mu.Lock()
	defer l.mu.Unlock()

	// Update the last receipt in-place with context
	idx := len(l.receipts) - 1
	l.receipts[idx].TenantID = tenantID
	l.receipts[idx].RunID = runID
	l.receipts[idx].PolicyRef = policyRef
	l.receipts[idx].EnvelopeRef = envelopeRef

	receipt.TenantID = tenantID
	receipt.RunID = runID
	receipt.PolicyRef = policyRef
	receipt.EnvelopeRef = envelopeRef
	return receipt
}

// Get retrieves a denial by receipt ID.
func (l *DenialLedger) Get(receiptID string) (*DenialReceipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for _, r := range l.receipts {
		if r.ReceiptID == receiptID {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("denial receipt %q not found", receiptID)
}

// QueryByReason returns all denials for a given reason.
func (l *DenialLedger) QueryByReason(reason DenialReason) []DenialReceipt {
	l.mu.Lock()
	defer l.mu.Unlock()

	var result []DenialReceipt
	for _, r := range l.receipts {
		if r.Reason == reason {
			result = append(result, r)
		}
	}
	return result
}

// QueryByPrincipal returns all denials for a given principal.
func (l *DenialLedger) QueryByPrincipal(principal string) []DenialReceipt {
	l.mu.Lock()
	defer l.mu.Unlock()

	var result []DenialReceipt
	for _, r := range l.receipts {
		if r.Principal == principal {
			result = append(result, r)
		}
	}
	return result
}

// Length returns the number of denials.
func (l *DenialLedger) Length() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.receipts)
}
