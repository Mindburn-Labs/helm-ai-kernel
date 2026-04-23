// Package economic — Procurement.
//
// Per HELM 2030 Spec §5.7:
//
//	Procurement actions are governance-bound acquisition flows.
//	Every procurement begins with a SpendIntent and results in a
//	TransactionManifest with vendor binding.
package economic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// ProcurementStatus tracks procurement lifecycle.
type ProcurementStatus string

const (
	ProcStatusDraft      ProcurementStatus = "DRAFT"
	ProcStatusSubmitted  ProcurementStatus = "SUBMITTED"
	ProcStatusApproved   ProcurementStatus = "APPROVED"
	ProcStatusInProgress ProcurementStatus = "IN_PROGRESS"
	ProcStatusCompleted  ProcurementStatus = "COMPLETED"
	ProcStatusCancelled  ProcurementStatus = "CANCELLED"
)

// ProcurementType classifies the acquisition.
type ProcurementType string

const (
	ProcTypeService      ProcurementType = "SERVICE"
	ProcTypeSubscription ProcurementType = "SUBSCRIPTION"
	ProcTypeLicense      ProcurementType = "LICENSE"
	ProcTypeHardware     ProcurementType = "HARDWARE"
	ProcTypeConsulting   ProcurementType = "CONSULTING"
	ProcTypeOneTime      ProcurementType = "ONE_TIME"
)

// ProcurementRequest is a governed acquisition request.
type ProcurementRequest struct {
	ID            string            `json:"id"`
	TenantID      string            `json:"tenant_id"`
	SpendIntentID string            `json:"spend_intent_id"`
	VendorID      string            `json:"vendor_id"`
	Type          ProcurementType   `json:"type"`
	Description   string            `json:"description"`
	AmountCents   int64             `json:"amount_cents"`
	Currency      string            `json:"currency"`
	Recurring     bool              `json:"recurring"`
	RecurInterval string            `json:"recur_interval,omitempty"` // "monthly", "quarterly", "annual"
	Status        ProcurementStatus `json:"status"`
	RequestedBy   string            `json:"requested_by"`
	ApprovedBy    string            `json:"approved_by,omitempty"`
	ManifestID    string            `json:"manifest_id,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	ContentHash   string            `json:"content_hash"`
}

// NewProcurementRequest creates a procurement request.
func NewProcurementRequest(id, tenantID, spendIntentID, vendorID, description, requestedBy, currency string, procType ProcurementType, amountCents int64) *ProcurementRequest {
	now := time.Now().UTC()
	pr := &ProcurementRequest{
		ID:            id,
		TenantID:      tenantID,
		SpendIntentID: spendIntentID,
		VendorID:      vendorID,
		Type:          procType,
		Description:   description,
		AmountCents:   amountCents,
		Currency:      currency,
		Status:        ProcStatusDraft,
		RequestedBy:   requestedBy,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	pr.ContentHash = pr.computeHash()
	return pr
}

// Submit transitions from DRAFT to SUBMITTED.
func (pr *ProcurementRequest) Submit() error {
	if pr.Status != ProcStatusDraft {
		return errors.New("procurement: can only submit from DRAFT status")
	}
	pr.Status = ProcStatusSubmitted
	pr.UpdatedAt = time.Now().UTC()
	pr.ContentHash = pr.computeHash()
	return nil
}

// Approve transitions from SUBMITTED to APPROVED.
func (pr *ProcurementRequest) Approve(approvedBy string) error {
	if pr.Status != ProcStatusSubmitted {
		return errors.New("procurement: can only approve from SUBMITTED status")
	}
	pr.Status = ProcStatusApproved
	pr.ApprovedBy = approvedBy
	pr.UpdatedAt = time.Now().UTC()
	pr.ContentHash = pr.computeHash()
	return nil
}

// BindManifest associates a transaction manifest.
func (pr *ProcurementRequest) BindManifest(manifestID string) {
	pr.ManifestID = manifestID
	pr.Status = ProcStatusInProgress
	pr.UpdatedAt = time.Now().UTC()
	pr.ContentHash = pr.computeHash()
}

// Validate ensures the request is well-formed.
func (pr *ProcurementRequest) Validate() error {
	if pr.ID == "" {
		return errors.New("procurement: id is required")
	}
	if pr.TenantID == "" {
		return errors.New("procurement: tenant_id is required")
	}
	if pr.VendorID == "" {
		return errors.New("procurement: vendor_id is required")
	}
	if pr.AmountCents <= 0 {
		return errors.New("procurement: amount_cents must be positive")
	}
	if pr.Type == "" {
		return errors.New("procurement: type is required")
	}
	return nil
}

func (pr *ProcurementRequest) computeHash() string {
	canon, _ := json.Marshal(struct {
		ID       string            `json:"id"`
		TenantID string            `json:"tenant_id"`
		VendorID string            `json:"vendor_id"`
		Type     ProcurementType   `json:"type"`
		Amount   int64             `json:"amount_cents"`
		Status   ProcurementStatus `json:"status"`
	}{pr.ID, pr.TenantID, pr.VendorID, pr.Type, pr.AmountCents, pr.Status})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
