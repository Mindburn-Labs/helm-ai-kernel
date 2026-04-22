// Package economic — Reconciliation.
//
// Per HELM 2030 Spec §5.7:
//
//	Reconciliation is the process of comparing expected vs actual spend
//	and flagging discrepancies for governance review.
package economic

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// ReconciliationStatus tracks the lifecycle of reconciliation.
type ReconciliationStatus string

const (
	ReconStatusPending    ReconciliationStatus = "PENDING"
	ReconStatusMatched    ReconciliationStatus = "MATCHED"
	ReconStatusDiscrepant ReconciliationStatus = "DISCREPANT"
	ReconStatusResolved   ReconciliationStatus = "RESOLVED"
	ReconStatusEscalated  ReconciliationStatus = "ESCALATED"
)

// Discrepancy records a mismatch between expected and actual.
type Discrepancy struct {
	TransactionID string `json:"transaction_id"`
	ExpectedCents int64  `json:"expected_cents"`
	ActualCents   int64  `json:"actual_cents"`
	DeltaCents    int64  `json:"delta_cents"`
	Reason        string `json:"reason"`
}

// ReconciliationRecord is the canonical reconciliation audit object.
type ReconciliationRecord struct {
	ID               string               `json:"id"`
	TenantID         string               `json:"tenant_id"`
	PeriodStart      time.Time            `json:"period_start"`
	PeriodEnd        time.Time            `json:"period_end"`
	TreasuryID       string               `json:"treasury_id"`
	ExpectedSpend    int64                `json:"expected_spend_cents"`
	ActualSpend      int64                `json:"actual_spend_cents"`
	Discrepancies    []Discrepancy        `json:"discrepancies,omitempty"`
	Status           ReconciliationStatus `json:"status"`
	ResolvedBy       string               `json:"resolved_by,omitempty"`
	ResolvedAt       *time.Time           `json:"resolved_at,omitempty"`
	CreatedAt        time.Time            `json:"created_at"`
	ContentHash      string               `json:"content_hash"`
}

// NewReconciliationRecord creates a reconciliation record.
func NewReconciliationRecord(id, tenantID, treasuryID string, periodStart, periodEnd time.Time, expectedSpend, actualSpend int64) *ReconciliationRecord {
	r := &ReconciliationRecord{
		ID:            id,
		TenantID:      tenantID,
		TreasuryID:    treasuryID,
		PeriodStart:   periodStart,
		PeriodEnd:     periodEnd,
		ExpectedSpend: expectedSpend,
		ActualSpend:   actualSpend,
		CreatedAt:     time.Now().UTC(),
	}
	if expectedSpend == actualSpend {
		r.Status = ReconStatusMatched
	} else {
		r.Status = ReconStatusDiscrepant
		r.Discrepancies = []Discrepancy{{
			TransactionID: "aggregate",
			ExpectedCents: expectedSpend,
			ActualCents:   actualSpend,
			DeltaCents:    actualSpend - expectedSpend,
			Reason:        "period aggregate mismatch",
		}}
	}
	r.ContentHash = r.computeHash()
	return r
}

// IsBalanced returns true if expected equals actual.
func (r *ReconciliationRecord) IsBalanced() bool {
	return r.ExpectedSpend == r.ActualSpend
}

// AddDiscrepancy records an individual discrepancy and re-hashes.
func (r *ReconciliationRecord) AddDiscrepancy(d Discrepancy) {
	r.Discrepancies = append(r.Discrepancies, d)
	r.Status = ReconStatusDiscrepant
	r.ContentHash = r.computeHash()
}

// Resolve marks the record as resolved.
func (r *ReconciliationRecord) Resolve(resolvedBy string) error {
	if r.Status != ReconStatusDiscrepant && r.Status != ReconStatusEscalated {
		return errors.New("reconciliation: can only resolve from DISCREPANT or ESCALATED status")
	}
	now := time.Now().UTC()
	r.Status = ReconStatusResolved
	r.ResolvedBy = resolvedBy
	r.ResolvedAt = &now
	r.ContentHash = r.computeHash()
	return nil
}

// Validate ensures the record is well-formed.
func (r *ReconciliationRecord) Validate() error {
	if r.ID == "" {
		return errors.New("reconciliation: id is required")
	}
	if r.TenantID == "" {
		return errors.New("reconciliation: tenant_id is required")
	}
	if r.TreasuryID == "" {
		return errors.New("reconciliation: treasury_id is required")
	}
	if r.PeriodEnd.Before(r.PeriodStart) {
		return errors.New("reconciliation: period_end must be after period_start")
	}
	return nil
}

func (r *ReconciliationRecord) computeHash() string {
	canon, _ := json.Marshal(struct {
		ID       string               `json:"id"`
		TenantID string               `json:"tenant_id"`
		Expected int64                `json:"expected"`
		Actual   int64                `json:"actual"`
		Status   ReconciliationStatus `json:"status"`
		Discreps int                  `json:"discrepancy_count"`
	}{r.ID, r.TenantID, r.ExpectedSpend, r.ActualSpend, r.Status, len(r.Discrepancies)})
	h := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(h[:])
}
