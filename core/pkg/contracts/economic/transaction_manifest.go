// Package economic — TransactionManifest.
//
// Per HELM 2030 Spec §5.7:
//
//	A TransactionManifest binds a SpendIntent to treasury, vendor, and
//	approval chain. It is the auditable record of an economic action.
package economic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// TransactionStatus tracks manifest lifecycle.
type TransactionStatus string

const (
	TxStatusPending   TransactionStatus = "PENDING"
	TxStatusApproved  TransactionStatus = "APPROVED"
	TxStatusExecuting TransactionStatus = "EXECUTING"
	TxStatusCompleted TransactionStatus = "COMPLETED"
	TxStatusFailed    TransactionStatus = "FAILED"
	TxStatusReversed  TransactionStatus = "REVERSED"
)

// LineItem represents a single cost line within a transaction.
type LineItem struct {
	Description string `json:"description"`
	AmountCents int64  `json:"amount_cents"`
	Category    string `json:"category"`
	EffectID    string `json:"effect_id,omitempty"`
}

// ApprovalRecord is evidence that a principal approved this transaction.
type ApprovalRecord struct {
	ApproverID string    `json:"approver_id"`
	ApprovedAt time.Time `json:"approved_at"`
	Scope      string    `json:"scope"`
	Signature  string    `json:"signature,omitempty"`
}

// TransactionManifest is the canonical record of an economic action.
// It binds spend intent → treasury → vendor → approval chain → receipt.
type TransactionManifest struct {
	ID                 string            `json:"id"`
	TenantID           string            `json:"tenant_id"`
	SpendIntentID      string            `json:"spend_intent_id"`
	VendorID           string            `json:"vendor_id,omitempty"`
	TreasuryAccountID  string            `json:"treasury_account_id"`
	TotalAmountCents   int64             `json:"total_amount_cents"`
	Currency           string            `json:"currency"`
	LineItems          []LineItem        `json:"line_items"`
	ApprovalChain      []ApprovalRecord  `json:"approval_chain"`
	Status             TransactionStatus `json:"status"`
	ReceiptHash        string            `json:"receipt_hash,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
	CompletedAt        *time.Time        `json:"completed_at,omitempty"`
	ContentHash        string            `json:"content_hash"`
}

// NewTransactionManifest creates a manifest with deterministic hash.
func NewTransactionManifest(id, tenantID, spendIntentID, treasuryAccountID, currency string, lineItems []LineItem) *TransactionManifest {
	var total int64
	for _, li := range lineItems {
		total += li.AmountCents
	}
	now := time.Now().UTC()
	tm := &TransactionManifest{
		ID:                id,
		TenantID:          tenantID,
		SpendIntentID:     spendIntentID,
		TreasuryAccountID: treasuryAccountID,
		TotalAmountCents:  total,
		Currency:          currency,
		LineItems:         lineItems,
		Status:            TxStatusPending,
		CreatedAt:         now,
	}
	tm.ContentHash = tm.computeHash()
	return tm
}

// AddApproval records an approval and re-hashes.
func (tm *TransactionManifest) AddApproval(approverID, scope, signature string) {
	tm.ApprovalChain = append(tm.ApprovalChain, ApprovalRecord{
		ApproverID: approverID,
		ApprovedAt: time.Now().UTC(),
		Scope:      scope,
		Signature:  signature,
	})
	tm.ContentHash = tm.computeHash()
}

// Complete transitions to COMPLETED and records completion time.
func (tm *TransactionManifest) Complete(receiptHash string) error {
	if tm.Status != TxStatusExecuting {
		return errors.New("transaction_manifest: can only complete from EXECUTING status")
	}
	now := time.Now().UTC()
	tm.Status = TxStatusCompleted
	tm.ReceiptHash = receiptHash
	tm.CompletedAt = &now
	tm.ContentHash = tm.computeHash()
	return nil
}

// Execute transitions from APPROVED to EXECUTING.
func (tm *TransactionManifest) Execute() error {
	if tm.Status != TxStatusApproved {
		return errors.New("transaction_manifest: can only execute from APPROVED status")
	}
	tm.Status = TxStatusExecuting
	tm.ContentHash = tm.computeHash()
	return nil
}

// Validate ensures the manifest is well-formed.
func (tm *TransactionManifest) Validate() error {
	if tm.ID == "" {
		return errors.New("transaction_manifest: id is required")
	}
	if tm.TenantID == "" {
		return errors.New("transaction_manifest: tenant_id is required")
	}
	if tm.SpendIntentID == "" {
		return errors.New("transaction_manifest: spend_intent_id is required")
	}
	if tm.TreasuryAccountID == "" {
		return errors.New("transaction_manifest: treasury_account_id is required")
	}
	if tm.TotalAmountCents <= 0 {
		return errors.New("transaction_manifest: total_amount_cents must be positive")
	}
	if len(tm.LineItems) == 0 {
		return errors.New("transaction_manifest: at least one line item required")
	}
	// Verify line items sum to total
	var sum int64
	for _, li := range tm.LineItems {
		sum += li.AmountCents
	}
	if sum != tm.TotalAmountCents {
		return errors.New("transaction_manifest: line item sum does not match total")
	}
	return nil
}

// LineItemTotal computes the sum of all line items.
func (tm *TransactionManifest) LineItemTotal() int64 {
	var total int64
	for _, li := range tm.LineItems {
		total += li.AmountCents
	}
	return total
}

func (tm *TransactionManifest) computeHash() string {
	canon, _ := json.Marshal(struct {
		ID          string            `json:"id"`
		TenantID    string            `json:"tenant_id"`
		SpendIntent string            `json:"spend_intent_id"`
		Treasury    string            `json:"treasury_account_id"`
		Total       int64             `json:"total_amount_cents"`
		Status      TransactionStatus `json:"status"`
		Receipt     string            `json:"receipt_hash"`
		Approvals   int               `json:"approval_count"`
	}{tm.ID, tm.TenantID, tm.SpendIntentID, tm.TreasuryAccountID, tm.TotalAmountCents, tm.Status, tm.ReceiptHash, len(tm.ApprovalChain)})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
