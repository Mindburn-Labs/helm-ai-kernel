// Package economic defines canonical economic governance primitives.
//
// Per HELM 2030 Spec §5.7 / §8.1:
//
//	Base economic schemas (spend intent, treasury, vendor, transaction manifest)
//	MUST remain in OSS. Their absence triggers the §8.3.3 forbidden failure mode.
package economic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SpendCategory classifies the nature of a spend intent.
type SpendCategory string

const (
	SpendOperational    SpendCategory = "OPERATIONAL"
	SpendInfrastructure SpendCategory = "INFRASTRUCTURE"
	SpendAICompute      SpendCategory = "AI_COMPUTE"
	SpendVendorService  SpendCategory = "VENDOR_SERVICE"
	SpendProcurement    SpendCategory = "PROCUREMENT"
	SpendHumanLabor     SpendCategory = "HUMAN_LABOR"
)

// SpendStatus tracks the lifecycle of a spend intent.
type SpendStatus string

const (
	SpendStatusDraft     SpendStatus = "DRAFT"
	SpendStatusPending   SpendStatus = "PENDING_APPROVAL"
	SpendStatusApproved  SpendStatus = "APPROVED"
	SpendStatusExecuted  SpendStatus = "EXECUTED"
	SpendStatusRejected  SpendStatus = "REJECTED"
	SpendStatusCancelled SpendStatus = "CANCELLED"
)

// SpendIntent represents a canonical request to incur cost.
// Every economic action in a HELM-governed org begins as a SpendIntent.
type SpendIntent struct {
	ID                    string            `json:"id"`
	TenantID              string            `json:"tenant_id"`
	Description           string            `json:"description"`
	AmountCents           int64             `json:"amount_cents"`
	Currency              string            `json:"currency"`
	Category              SpendCategory     `json:"category"`
	RequiredApprovalLevel int               `json:"required_approval_level"`
	BudgetID              string            `json:"budget_id"`
	VendorID              string            `json:"vendor_id,omitempty"`
	Justification         string            `json:"justification"`
	RequestedBy           string            `json:"requested_by"`
	Status                SpendStatus       `json:"status"`
	Metadata              map[string]string `json:"metadata,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
	ContentHash           string            `json:"content_hash"`
}

// NewSpendIntent creates a SpendIntent with a deterministic content hash.
func NewSpendIntent(id, tenantID, description string, amountCents int64, currency string, category SpendCategory, budgetID, requestedBy, justification string) *SpendIntent {
	now := time.Now().UTC()
	si := &SpendIntent{
		ID:            id,
		TenantID:      tenantID,
		Description:   description,
		AmountCents:   amountCents,
		Currency:      currency,
		Category:      category,
		BudgetID:      budgetID,
		RequestedBy:   requestedBy,
		Justification: justification,
		Status:        SpendStatusDraft,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	si.ContentHash = si.computeHash()
	return si
}

// Validate ensures the SpendIntent is well-formed. Fails closed on invalid data.
func (si *SpendIntent) Validate() error {
	if si.ID == "" {
		return errors.New("spend_intent: id is required")
	}
	if si.TenantID == "" {
		return errors.New("spend_intent: tenant_id is required")
	}
	if si.AmountCents <= 0 {
		return errors.New("spend_intent: amount_cents must be positive")
	}
	if si.Currency == "" {
		return errors.New("spend_intent: currency is required")
	}
	if si.BudgetID == "" {
		return errors.New("spend_intent: budget_id is required")
	}
	if si.RequestedBy == "" {
		return errors.New("spend_intent: requested_by is required")
	}
	if si.Category == "" {
		return errors.New("spend_intent: category is required")
	}
	return nil
}

// Approve transitions the intent to APPROVED status.
func (si *SpendIntent) Approve() error {
	if si.Status != SpendStatusPending {
		return fmt.Errorf("spend_intent: cannot approve from status %s", si.Status)
	}
	si.Status = SpendStatusApproved
	si.UpdatedAt = time.Now().UTC()
	si.ContentHash = si.computeHash()
	return nil
}

// Submit transitions the intent from DRAFT to PENDING_APPROVAL.
func (si *SpendIntent) Submit() error {
	if si.Status != SpendStatusDraft {
		return fmt.Errorf("spend_intent: cannot submit from status %s", si.Status)
	}
	si.Status = SpendStatusPending
	si.UpdatedAt = time.Now().UTC()
	si.ContentHash = si.computeHash()
	return nil
}

// Reject transitions from PENDING_APPROVAL to REJECTED.
func (si *SpendIntent) Reject() error {
	if si.Status != SpendStatusPending {
		return fmt.Errorf("spend_intent: cannot reject from status %s", si.Status)
	}
	si.Status = SpendStatusRejected
	si.UpdatedAt = time.Now().UTC()
	si.ContentHash = si.computeHash()
	return nil
}

func (si *SpendIntent) computeHash() string {
	canon, _ := json.Marshal(struct {
		ID          string        `json:"id"`
		TenantID    string        `json:"tenant_id"`
		Amount      int64         `json:"amount_cents"`
		Currency    string        `json:"currency"`
		Category    SpendCategory `json:"category"`
		BudgetID    string        `json:"budget_id"`
		RequestedBy string        `json:"requested_by"`
		Status      SpendStatus   `json:"status"`
	}{si.ID, si.TenantID, si.AmountCents, si.Currency, si.Category, si.BudgetID, si.RequestedBy, si.Status})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
