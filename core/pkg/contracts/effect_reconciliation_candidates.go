package contracts

import (
	"errors"
	"fmt"
)

const (
	EffectReconciliationCandidatesSchemaV1   = "effect-reconciliation-candidates.v1"
	EffectReconciliationCandidatesContractV1 = "2026-07-23"
)

var ErrEffectReconciliationCandidatesInvalid = errors.New("effect reconciliation candidates invalid")

// EffectReconciliationCandidates is a Kernel-owned snapshot for constructing a
// later RECONCILE_SOURCE command. It is deliberately not an effect permit.
// The command recorder must reread the current FENCE and reservation head.
type EffectReconciliationCandidates struct {
	SchemaVersion      string `json:"schema_version"`
	ContractVersion    string `json:"contract_version"`
	ExecutionAuthority string `json:"execution_authority"`

	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Audience    string `json:"audience"`

	Fence      EffectReconciliationFence       `json:"fence"`
	Candidates []EffectReconciliationCandidate `json:"candidates"`
}

// EffectReconciliationFence binds every candidate to the FENCE observed by
// the Kernel in one durable scope transaction.
type EffectReconciliationFence struct {
	CommandID   string `json:"command_id"`
	CommandHash string `json:"command_hash"`
	Epoch       uint64 `json:"epoch"`
	ReceiptHash string `json:"receipt_hash"`
}

// EffectReconciliationCandidate contains only immutable command bindings and
// no generic reservation payload or connector-effect authority.
type EffectReconciliationCandidate struct {
	AdmissionID string `json:"admission_id"`
	AttemptID   string `json:"attempt_id"`

	ReservationSequence uint64 `json:"reservation_sequence"`
	ReservationHeadHash string `json:"reservation_head_hash"`
	ReservationState    string `json:"reservation_state"`

	ConnectorID           string `json:"connector_id"`
	ConnectorVersion      string `json:"connector_version"`
	ConnectorAction       string `json:"connector_action"`
	ConnectorExecutionRef string `json:"connector_execution_ref"`
	ProofSessionRef       string `json:"proof_session_ref,omitempty"`
	IntentRef             string `json:"intent_ref"`
	EffectRef             string `json:"effect_ref,omitempty"`

	IdempotencyKeyHash string `json:"idempotency_key_hash"`
	EffectHash         string `json:"effect_hash"`

	NextDispositionSequence uint64 `json:"next_disposition_sequence"`
	PreviousReceiptHash     string `json:"previous_receipt_hash,omitempty"`
}

func (p EffectReconciliationCandidates) Validate() error {
	if p.SchemaVersion != EffectReconciliationCandidatesSchemaV1 ||
		p.ContractVersion != EffectReconciliationCandidatesContractV1 ||
		p.ExecutionAuthority != EffectDispositionExecutionAuthorityNone {
		return effectReconciliationCandidatesInvalid("unsupported contract or execution authority")
	}
	for field, value := range map[string]string{
		"tenant_id": p.TenantID, "workspace_id": p.WorkspaceID, "audience": p.Audience,
		"fence.command_id": p.Fence.CommandID,
	} {
		if !isApprovalGrantToken(value) || len(value) > 512 {
			return effectReconciliationCandidatesInvalid(field + " is invalid")
		}
	}
	for field, value := range map[string]string{
		"fence.command_hash": p.Fence.CommandHash,
		"fence.receipt_hash": p.Fence.ReceiptHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return effectReconciliationCandidatesInvalid(field + " is invalid")
		}
	}
	if p.Fence.Epoch == 0 || p.Fence.Epoch > ConnectorReleaseAuthorityMaxRevision {
		return effectReconciliationCandidatesInvalid("fence epoch is invalid")
	}

	seen := make(map[string]struct{}, len(p.Candidates))
	for _, candidate := range p.Candidates {
		if err := candidate.Validate(); err != nil {
			return err
		}
		if _, duplicate := seen[candidate.AdmissionID]; duplicate {
			return effectReconciliationCandidatesInvalid("duplicate admission_id")
		}
		seen[candidate.AdmissionID] = struct{}{}
	}
	return nil
}

func (c EffectReconciliationCandidate) Validate() error {
	for field, value := range map[string]string{
		"admission_id": c.AdmissionID, "attempt_id": c.AttemptID,
		"connector_id": c.ConnectorID, "connector_version": c.ConnectorVersion,
		"connector_action": c.ConnectorAction, "connector_execution_ref": c.ConnectorExecutionRef,
		"intent_ref": c.IntentRef,
	} {
		if !isApprovalGrantToken(value) || len(value) > 512 {
			return effectReconciliationCandidatesInvalid(field + " is invalid")
		}
	}
	for field, value := range map[string]string{
		"reservation_head_hash": c.ReservationHeadHash,
		"idempotency_key_hash":  c.IdempotencyKeyHash,
		"effect_hash":           c.EffectHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return effectReconciliationCandidatesInvalid(field + " is invalid")
		}
	}
	if c.ReservationSequence == 0 || c.ReservationSequence > ConnectorReleaseAuthorityMaxRevision ||
		c.NextDispositionSequence == 0 || c.NextDispositionSequence > ConnectorReleaseAuthorityMaxRevision {
		return effectReconciliationCandidatesInvalid("candidate sequence is invalid")
	}
	switch c.ReservationState {
	case EffectClosePriorStateStarted, EffectClosePriorStateUncertain:
	default:
		return effectReconciliationCandidatesInvalid("reservation_state must be STARTED or UNCERTAIN")
	}
	if c.NextDispositionSequence == 1 {
		if c.PreviousReceiptHash != "" {
			return effectReconciliationCandidatesInvalid("first disposition candidate must not claim previous_receipt_hash")
		}
	} else if !isApprovalGrantSHA256(c.PreviousReceiptHash) {
		return effectReconciliationCandidatesInvalid("successor disposition candidate requires previous_receipt_hash")
	}
	for field, value := range map[string]string{
		"proof_session_ref": c.ProofSessionRef,
		"effect_ref":        c.EffectRef,
	} {
		if value != "" && (!isApprovalGrantToken(value) || len(value) > 512) {
			return effectReconciliationCandidatesInvalid(field + " is invalid")
		}
	}
	return nil
}

func effectReconciliationCandidatesInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrEffectReconciliationCandidatesInvalid, message)
}
