package governance

import (
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

// DenialReceipt records the reason and context for a refused action.
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

// DenialLedger preserves the type of the retired in-memory denial ledger.
type DenialLedger struct {
	mu       sync.Mutex
	receipts []DenialReceipt
	seq      int64
	clock    func() time.Time
}
