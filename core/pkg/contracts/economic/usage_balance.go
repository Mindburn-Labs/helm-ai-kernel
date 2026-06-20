package economic

import (
	"errors"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

// BalanceMovementType classifies a non-usage movement against a usage balance.
//
// Usage debits are already evidenced by UsageReceipt + SettlementReceipt. Every
// other balance movement (funding, promotion, refund, accrual, or a manual
// correction) is evidenced by a BalanceMovementReceipt so the SPEND5 invariant
// "every balance movement references a receipt hash" holds for the whole
// lifecycle, not only for metered usage.
type BalanceMovementType string

const (
	// BalanceMovementTopUp adds prepaid funds to the usage balance.
	BalanceMovementTopUp BalanceMovementType = "TOP_UP"
	// BalanceMovementPromoCredit adds promotional (non-cash) credit.
	BalanceMovementPromoCredit BalanceMovementType = "PROMO_CREDIT"
	// BalanceMovementRefund returns funds for a reversed/failed usage debit.
	BalanceMovementRefund BalanceMovementType = "REFUND"
	// BalanceMovementCorrection is an append-only manual adjustment that requires
	// an approval ceremony. It never edits prior history.
	BalanceMovementCorrection BalanceMovementType = "CORRECTION"
	// BalanceMovementProviderCostAccrual accrues raw provider cost for export.
	BalanceMovementProviderCostAccrual BalanceMovementType = "PROVIDER_COST_ACCRUAL"
	// BalanceMovementPlatformFeeAccrual accrues the Mindburn platform fee.
	BalanceMovementPlatformFeeAccrual BalanceMovementType = "PLATFORM_FEE_ACCRUAL"
	// BalanceMovementInvoiceAccrual accrues enterprise-invoiced (deferred) spend.
	BalanceMovementInvoiceAccrual BalanceMovementType = "INVOICE_ACCRUAL"
)

// fundingDirection reports the credit/debit direction a funding movement posts
// when the caller does not override it. Funding movements (top-up, promo,
// refund) credit the balance; corrections override this with an explicit
// direction before sealing.
func (t BalanceMovementType) fundingDirection() SettlementDirection {
	return SettlementCredit
}

// IsAccrual reports whether the movement is bookkeeping-only and must not move
// the cash balance. Accruals feed the finance export but never debit/credit the
// available usage balance.
func (t BalanceMovementType) IsAccrual() bool {
	switch t {
	case BalanceMovementProviderCostAccrual, BalanceMovementPlatformFeeAccrual, BalanceMovementInvoiceAccrual:
		return true
	default:
		return false
	}
}

// LedgerEntryType maps a movement to the typed UsageLedgerEntry it posts.
func (t BalanceMovementType) LedgerEntryType() UsageLedgerEntryType {
	switch t {
	case BalanceMovementCorrection:
		return UsageLedgerAdjustment
	default:
		return UsageLedgerCredit
	}
}

// correctionApproved reports whether a sealed approval ceremony actually
// authorizes a manual correction under dual control: the ceremony must be
// approved and at least one approver must differ from the requester.
func correctionApproved(a *contracts.ApprovalCeremony) error {
	if a == nil {
		return errors.New("balance_movement_receipt: correction requires an approval ceremony")
	}
	if err := a.Validate(); err != nil {
		return err
	}
	if a.State != contracts.ApprovalCeremonyAllowed {
		return errors.New("balance_movement_receipt: correction approval ceremony is not approved")
	}
	distinct := false
	for _, approver := range a.Approvers {
		if approver != "" && approver != a.RequestedBy {
			distinct = true
			break
		}
	}
	if !distinct {
		return errors.New("balance_movement_receipt: correction requires an approver distinct from the requester (dual control)")
	}
	return nil
}

// BalanceMovementReceipt is the content-addressed receipt for one non-usage
// movement against a usage balance. It is the funding/correction analogue of
// UsageReceipt: every top-up, promo, refund, accrual, or manual correction
// produces one, and the resulting UsageLedgerEntry binds its ContentHash.
type BalanceMovementReceipt struct {
	ID               string              `json:"id"`
	TenantID         string              `json:"tenant_id"`
	BalanceAccountID string              `json:"balance_account_id"`
	Type             BalanceMovementType `json:"type"`
	Direction        SettlementDirection `json:"direction"`
	AmountCents      int64               `json:"amount_cents"`
	Currency         string              `json:"currency"`
	IdempotencyKey   string              `json:"idempotency_key"`
	Reason           string              `json:"reason,omitempty"`
	// SourceReceiptHash links a REFUND back to the UsageReceipt it reverses.
	SourceReceiptHash string `json:"source_receipt_hash,omitempty"`
	// Approval is required for CORRECTION movements (the approval ceremony).
	Approval        *contracts.ApprovalCeremony `json:"approval,omitempty"`
	EvidencePackRef string                      `json:"evidence_pack_ref"`
	CreatedAt       time.Time                   `json:"created_at"`
	ContentHash     string                      `json:"content_hash"`
}

// NewBalanceMovementReceipt builds a movement receipt with a deterministic hash.
// The direction defaults to the funding direction (CREDIT); callers override
// Direction for CORRECTION debits before calling Reseal.
func NewBalanceMovementReceipt(id, tenantID, balanceAccountID string, movementType BalanceMovementType, amountCents int64, currency, idempotencyKey, evidencePackRef string) *BalanceMovementReceipt {
	r := &BalanceMovementReceipt{
		ID:               id,
		TenantID:         tenantID,
		BalanceAccountID: balanceAccountID,
		Type:             movementType,
		Direction:        movementType.fundingDirection(),
		AmountCents:      amountCents,
		Currency:         currency,
		IdempotencyKey:   idempotencyKey,
		EvidencePackRef:  evidencePackRef,
		CreatedAt:        time.Now().UTC(),
	}
	r.ContentHash = r.computeHash()
	return r
}

// Reseal recomputes ContentHash after post-construction fields (Direction,
// Approval, SourceReceiptHash, Reason) are populated.
func (r *BalanceMovementReceipt) Reseal() string {
	if r == nil {
		return ""
	}
	r.ContentHash = r.computeHash()
	return r.ContentHash
}

// LedgerEntryType maps a movement to the typed UsageLedgerEntry it posts.
func (r *BalanceMovementReceipt) LedgerEntryType() UsageLedgerEntryType {
	return r.Type.LedgerEntryType()
}

// Validate ensures the movement receipt can back a balance ledger entry.
func (r *BalanceMovementReceipt) Validate() error {
	if r == nil {
		return errors.New("balance_movement_receipt: receipt is nil")
	}
	if r.ID == "" {
		return errors.New("balance_movement_receipt: id is required")
	}
	if r.TenantID == "" {
		return errors.New("balance_movement_receipt: tenant_id is required")
	}
	if r.BalanceAccountID == "" {
		return errors.New("balance_movement_receipt: balance_account_id is required")
	}
	if r.Type == "" {
		return errors.New("balance_movement_receipt: type is required")
	}
	if r.Direction != SettlementDebit && r.Direction != SettlementCredit {
		return errors.New("balance_movement_receipt: direction must be DEBIT or CREDIT")
	}
	if r.AmountCents <= 0 {
		return errors.New("balance_movement_receipt: amount_cents must be positive")
	}
	if r.Currency == "" {
		return errors.New("balance_movement_receipt: currency is required")
	}
	if r.IdempotencyKey == "" {
		return errors.New("balance_movement_receipt: idempotency_key is required")
	}
	if r.EvidencePackRef == "" {
		return errors.New("balance_movement_receipt: evidence_pack_ref is required")
	}
	if r.Type == BalanceMovementRefund && r.SourceReceiptHash == "" {
		return errors.New("balance_movement_receipt: refund requires source_receipt_hash")
	}
	if r.Type == BalanceMovementCorrection {
		if r.Reason == "" {
			return errors.New("balance_movement_receipt: correction requires a reason")
		}
		if err := correctionApproved(r.Approval); err != nil {
			return err
		}
	}
	return nil
}

func (r *BalanceMovementReceipt) computeHash() string {
	return hashSpendAuthorityCanonical(struct {
		ID                string              `json:"id"`
		TenantID          string              `json:"tenant_id"`
		BalanceAccountID  string              `json:"balance_account_id"`
		Type              BalanceMovementType `json:"type"`
		Direction         SettlementDirection `json:"direction"`
		AmountCents       int64               `json:"amount_cents"`
		Currency          string              `json:"currency"`
		IdempotencyKey    string              `json:"idempotency_key"`
		Reason            string              `json:"reason,omitempty"`
		SourceReceiptHash string              `json:"source_receipt_hash,omitempty"`
		ApprovalID        string              `json:"approval_id,omitempty"`
		ApprovalHash      string              `json:"approval_hash,omitempty"`
		EvidencePackRef   string              `json:"evidence_pack_ref"`
	}{r.ID, r.TenantID, r.BalanceAccountID, r.Type, r.Direction, r.AmountCents, r.Currency, r.IdempotencyKey, r.Reason, r.SourceReceiptHash, ceremonyID(r.Approval), ceremonyHash(r.Approval), r.EvidencePackRef})
}

func ceremonyID(c *contracts.ApprovalCeremony) string {
	if c == nil {
		return ""
	}
	return c.ApprovalID
}

func ceremonyHash(c *contracts.ApprovalCeremony) string {
	if c == nil {
		return ""
	}
	return c.CeremonyHash
}
