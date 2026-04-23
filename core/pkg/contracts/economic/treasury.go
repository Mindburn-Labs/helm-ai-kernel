// Package economic — TreasuryAccount.
//
// Per HELM 2030 Spec §5.7:
//
//	Treasury is a first-class governance object. Every org has at least one
//	treasury account. All spend flows through treasury with receipt binding.
package economic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// AccountType classifies a treasury account.
type AccountType string

const (
	AccountOperating    AccountType = "OPERATING"
	AccountReserve      AccountType = "RESERVE"
	AccountEscrow       AccountType = "ESCROW"
	AccountVendorPrepay AccountType = "VENDOR_PREPAY"
)

// TreasuryLimit defines spending thresholds that trigger approval gates.
type TreasuryLimit struct {
	DailyMaxCents         int64 `json:"daily_max_cents"`
	MonthlyMaxCents       int64 `json:"monthly_max_cents"`
	RequiresApprovalAbove int64 `json:"requires_approval_above_cents"`
}

// HoldRecord represents a reserved-but-not-committed amount.
type HoldRecord struct {
	HoldID      string    `json:"hold_id"`
	AmountCents int64     `json:"amount_cents"`
	Purpose     string    `json:"purpose"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

// TreasuryAccount represents an org's financial account under governance.
type TreasuryAccount struct {
	ID           string            `json:"id"`
	TenantID     string            `json:"tenant_id"`
	Name         string            `json:"name"`
	AccountType  AccountType       `json:"account_type"`
	BalanceCents int64             `json:"balance_cents"`
	HeldCents    int64             `json:"held_cents"`
	Currency     string            `json:"currency"`
	Limits       TreasuryLimit     `json:"limits"`
	Holds        []HoldRecord      `json:"holds,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
	ContentHash  string            `json:"content_hash"`
}

// TreasuryReceipt is evidence of a treasury mutation.
type TreasuryReceipt struct {
	ReceiptID    string    `json:"receipt_id"`
	AccountID    string    `json:"account_id"`
	Operation    string    `json:"operation"` // "credit", "debit", "hold", "release"
	AmountCents  int64     `json:"amount_cents"`
	BalanceAfter int64     `json:"balance_after"`
	Reference    string    `json:"reference,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	ContentHash  string    `json:"content_hash"`
}

// NewTreasuryAccount creates a treasury account with computed hash.
func NewTreasuryAccount(id, tenantID, name string, accountType AccountType, currency string, limits TreasuryLimit) *TreasuryAccount {
	now := time.Now().UTC()
	ta := &TreasuryAccount{
		ID:          id,
		TenantID:    tenantID,
		Name:        name,
		AccountType: accountType,
		Currency:    currency,
		Limits:      limits,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	ta.ContentHash = ta.computeHash()
	return ta
}

// AvailableBalance returns balance minus held amounts.
func (ta *TreasuryAccount) AvailableBalance() int64 {
	avail := ta.BalanceCents - ta.HeldCents
	if avail < 0 {
		return 0
	}
	return avail
}

// Credit adds funds and returns a receipt.
func (ta *TreasuryAccount) Credit(receiptID string, amountCents int64, reference string) (*TreasuryReceipt, error) {
	if amountCents <= 0 {
		return nil, errors.New("treasury: credit amount must be positive")
	}
	ta.BalanceCents += amountCents
	ta.UpdatedAt = time.Now().UTC()
	ta.ContentHash = ta.computeHash()

	return ta.newReceipt(receiptID, "credit", amountCents, reference), nil
}

// Debit removes funds and returns a receipt. Fails closed if insufficient.
func (ta *TreasuryAccount) Debit(receiptID string, amountCents int64, reference string) (*TreasuryReceipt, error) {
	if amountCents <= 0 {
		return nil, errors.New("treasury: debit amount must be positive")
	}
	if ta.AvailableBalance() < amountCents {
		return nil, fmt.Errorf("treasury: insufficient available balance (%d < %d)", ta.AvailableBalance(), amountCents)
	}
	ta.BalanceCents -= amountCents
	ta.UpdatedAt = time.Now().UTC()
	ta.ContentHash = ta.computeHash()

	return ta.newReceipt(receiptID, "debit", amountCents, reference), nil
}

// Hold reserves funds without debiting. Fails closed if insufficient.
func (ta *TreasuryAccount) Hold(holdID string, amountCents int64, purpose string, expiresAt time.Time) (*TreasuryReceipt, error) {
	if amountCents <= 0 {
		return nil, errors.New("treasury: hold amount must be positive")
	}
	if ta.AvailableBalance() < amountCents {
		return nil, fmt.Errorf("treasury: insufficient available balance for hold (%d < %d)", ta.AvailableBalance(), amountCents)
	}
	ta.HeldCents += amountCents
	ta.Holds = append(ta.Holds, HoldRecord{
		HoldID:      holdID,
		AmountCents: amountCents,
		Purpose:     purpose,
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now().UTC(),
	})
	ta.UpdatedAt = time.Now().UTC()
	ta.ContentHash = ta.computeHash()

	return ta.newReceipt(holdID, "hold", amountCents, purpose), nil
}

// ReleaseHold releases a previously held amount.
func (ta *TreasuryAccount) ReleaseHold(holdID string) (*TreasuryReceipt, error) {
	for i, h := range ta.Holds {
		if h.HoldID == holdID {
			ta.HeldCents -= h.AmountCents
			ta.Holds = append(ta.Holds[:i], ta.Holds[i+1:]...)
			ta.UpdatedAt = time.Now().UTC()
			ta.ContentHash = ta.computeHash()
			return ta.newReceipt(holdID, "release", h.AmountCents, h.Purpose), nil
		}
	}
	return nil, fmt.Errorf("treasury: hold %s not found", holdID)
}

// Validate ensures the account is well-formed.
func (ta *TreasuryAccount) Validate() error {
	if ta.ID == "" {
		return errors.New("treasury: id is required")
	}
	if ta.TenantID == "" {
		return errors.New("treasury: tenant_id is required")
	}
	if ta.Currency == "" {
		return errors.New("treasury: currency is required")
	}
	if ta.BalanceCents < 0 {
		return errors.New("treasury: balance cannot be negative")
	}
	return nil
}

func (ta *TreasuryAccount) newReceipt(id, operation string, amountCents int64, reference string) *TreasuryReceipt {
	r := &TreasuryReceipt{
		ReceiptID:    id,
		AccountID:    ta.ID,
		Operation:    operation,
		AmountCents:  amountCents,
		BalanceAfter: ta.BalanceCents,
		Reference:    reference,
		Timestamp:    time.Now().UTC(),
	}
	canon, _ := json.Marshal(r)
	h := sha256.Sum256(canon)
	r.ContentHash = "sha256:" + hex.EncodeToString(h[:])
	return r
}

func (ta *TreasuryAccount) computeHash() string {
	canon, _ := json.Marshal(struct {
		ID          string      `json:"id"`
		TenantID    string      `json:"tenant_id"`
		AccountType AccountType `json:"account_type"`
		Balance     int64       `json:"balance_cents"`
		Held        int64       `json:"held_cents"`
		Currency    string      `json:"currency"`
	}{ta.ID, ta.TenantID, ta.AccountType, ta.BalanceCents, ta.HeldCents, ta.Currency})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
