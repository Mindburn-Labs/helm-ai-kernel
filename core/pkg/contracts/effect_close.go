package contracts

// quantum_posture: classical Ed25519 connector effect-close acknowledgement and
// receipt contract types only; no hybrid or post-quantum claim.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	ConnectorEffectAcknowledgementSchemaV1   = "connector-effect-acknowledgement.v1"
	ConnectorEffectAcknowledgementContractV1 = "2026-07-18"
	ConnectorEffectAcknowledgementAlgorithm  = "ed25519"
	ConnectorEffectOutcomeApplied            = "APPLIED"
	ConnectorEffectOutcomeNotApplied         = "NOT_APPLIED"

	EffectCloseReceiptSchemaV1     = "effect-close-receipt.v1"
	EffectCloseReceiptContractV1   = "2026-07-18"
	EffectCloseReceiptStateClosed  = "COMPLETED"
	EffectClosePriorStateStarted   = "STARTED"
	EffectClosePriorStateUncertain = "UNCERTAIN"
	EffectCloseMaxClockSkew        = 5 * time.Minute
)

var (
	ErrConnectorEffectAcknowledgementInvalid = errors.New("connector effect acknowledgement invalid")
	ErrEffectCloseReceiptInvalid             = errors.New("effect close receipt invalid")
)

// ConnectorEffectAcknowledgement is the connector-runtime statement about a
// source-system outcome. It is not Kernel closure authority: the Kernel must
// verify its detached signature, bind it to an exact reservation, and issue a
// separate EffectCloseReceipt before the reservation is terminal.
type ConnectorEffectAcknowledgement struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	AcknowledgementID string `json:"acknowledgement_id"`
	AdmissionID       string `json:"admission_id"`
	AttemptID         string `json:"attempt_id"`

	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Audience    string `json:"audience"`

	ConnectorID           string `json:"connector_id"`
	ConnectorVersion      string `json:"connector_version"`
	ConnectorAction       string `json:"connector_action"`
	ConnectorExecutionRef string `json:"connector_execution_ref"`
	ProofSessionRef       string `json:"proof_session_ref,omitempty"`
	IntentRef             string `json:"intent_ref"`

	IdempotencyKeyHash string `json:"idempotency_key_hash"`
	EffectHash         string `json:"effect_hash"`
	Outcome            string `json:"outcome"`
	ResponseHash       string `json:"response_hash"`
	EffectRef          string `json:"effect_ref,omitempty"`
	ReconciliationRef  string `json:"reconciliation_ref,omitempty"`

	IssuerID      string    `json:"issuer_id"`
	SigningKeyRef string    `json:"signing_key_ref"`
	Algorithm     string    `json:"algorithm"`
	ObservedAt    time.Time `json:"observed_at"`

	AcknowledgementHash string `json:"acknowledgement_hash,omitempty"`
}

// ConnectorEffectAcknowledgementEnvelope carries the detached connector
// acknowledgement signature. Trust comes from deployment-pinned issuer keys,
// never from key material embedded in this envelope.
type ConnectorEffectAcknowledgementEnvelope struct {
	Acknowledgement ConnectorEffectAcknowledgement `json:"acknowledgement"`
	Signature       string                         `json:"signature"`
}

func (a ConnectorEffectAcknowledgement) Validate() error {
	if a.SchemaVersion != ConnectorEffectAcknowledgementSchemaV1 {
		return connectorEffectAcknowledgementInvalid("unsupported schema_version")
	}
	if a.ContractVersion != ConnectorEffectAcknowledgementContractV1 {
		return connectorEffectAcknowledgementInvalid("unsupported contract_version")
	}
	if a.Algorithm != ConnectorEffectAcknowledgementAlgorithm {
		return connectorEffectAcknowledgementInvalid("unsupported algorithm")
	}
	for field, value := range map[string]string{
		"acknowledgement_id": a.AcknowledgementID,
		"admission_id":       a.AdmissionID, "attempt_id": a.AttemptID,
		"tenant_id": a.TenantID, "workspace_id": a.WorkspaceID, "audience": a.Audience,
		"connector_id": a.ConnectorID, "connector_version": a.ConnectorVersion,
		"connector_action": a.ConnectorAction, "connector_execution_ref": a.ConnectorExecutionRef,
		"intent_ref": a.IntentRef, "issuer_id": a.IssuerID, "signing_key_ref": a.SigningKeyRef,
	} {
		if !isApprovalGrantToken(value) || len(value) > 512 {
			return connectorEffectAcknowledgementInvalid(field + " is required and must be a bounded token")
		}
	}
	for field, value := range map[string]string{
		"idempotency_key_hash": a.IdempotencyKeyHash,
		"effect_hash":          a.EffectHash,
		"response_hash":        a.ResponseHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return connectorEffectAcknowledgementInvalid(field + " must be a lowercase sha256 reference")
		}
	}
	if a.ReconciliationRef != "" && (!isApprovalGrantToken(a.ReconciliationRef) || len(a.ReconciliationRef) > 512) {
		return connectorEffectAcknowledgementInvalid("reconciliation_ref must be a bounded token")
	}
	if a.ProofSessionRef != "" && (!isApprovalGrantToken(a.ProofSessionRef) || len(a.ProofSessionRef) > 512) {
		return connectorEffectAcknowledgementInvalid("proof_session_ref must be a bounded token")
	}
	switch a.Outcome {
	case ConnectorEffectOutcomeApplied:
		if !isApprovalGrantToken(a.EffectRef) || len(a.EffectRef) > 512 {
			return connectorEffectAcknowledgementInvalid("APPLIED requires a bounded effect_ref")
		}
	case ConnectorEffectOutcomeNotApplied:
		if a.EffectRef != "" {
			return connectorEffectAcknowledgementInvalid("NOT_APPLIED must not claim an effect_ref")
		}
	default:
		return connectorEffectAcknowledgementInvalid("unsupported outcome")
	}
	if a.ObservedAt.IsZero() || !isApprovalGrantUTC(a.ObservedAt) || !a.ObservedAt.Equal(a.ObservedAt.Truncate(time.Microsecond)) {
		return connectorEffectAcknowledgementInvalid("observed_at must use UTC microsecond precision")
	}
	if a.AcknowledgementHash != "" && !isApprovalGrantSHA256(a.AcknowledgementHash) {
		return connectorEffectAcknowledgementInvalid("acknowledgement_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (a ConnectorEffectAcknowledgement) Seal() (ConnectorEffectAcknowledgement, error) {
	if err := a.Validate(); err != nil {
		return ConnectorEffectAcknowledgement{}, err
	}
	a.AcknowledgementHash = ""
	hash, err := hashJCS(a)
	if err != nil {
		return ConnectorEffectAcknowledgement{}, connectorEffectAcknowledgementInvalid("seal: " + err.Error())
	}
	a.AcknowledgementHash = hash
	return a, nil
}

func (a ConnectorEffectAcknowledgement) ValidateIntegrity() error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.AcknowledgementHash == "" {
		return connectorEffectAcknowledgementInvalid("acknowledgement_hash is required")
	}
	sealed, err := a.Seal()
	if err != nil || sealed.AcknowledgementHash != a.AcknowledgementHash {
		return connectorEffectAcknowledgementInvalid("acknowledgement integrity mismatch")
	}
	return nil
}

func (e ConnectorEffectAcknowledgementEnvelope) Validate() error {
	if err := e.Acknowledgement.ValidateIntegrity(); err != nil {
		return err
	}
	raw, err := hex.DecodeString(e.Signature)
	if err != nil || len(raw) != 64 || hex.EncodeToString(raw) != e.Signature {
		return connectorEffectAcknowledgementInvalid("signature must be canonical lowercase Ed25519 hex")
	}
	return nil
}

// EffectCloseReceipt is the Kernel-signed terminal statement that binds an
// exact reservation head to a verified source acknowledgement and a sealed
// EvidencePack. COMPLETED means adjudicated and closed; Outcome says whether
// the external effect was actually applied.
type EffectCloseReceipt struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	CloseID string `json:"close_id"`
	State   string `json:"state"`

	AdmissionID string `json:"admission_id"`
	AttemptID   string `json:"attempt_id"`
	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Audience    string `json:"audience"`

	ConnectorID      string `json:"connector_id"`
	ConnectorVersion string `json:"connector_version"`
	ConnectorAction  string `json:"connector_action"`

	PriorState          string `json:"prior_state"`
	ReservationSequence uint64 `json:"reservation_sequence"`
	ReservationHeadHash string `json:"reservation_head_hash"`

	AcknowledgementHash string `json:"acknowledgement_hash"`
	Outcome             string `json:"outcome"`
	IdempotencyKeyHash  string `json:"idempotency_key_hash"`
	EffectHash          string `json:"effect_hash"`
	ResponseHash        string `json:"response_hash"`

	ConnectorExecutionRef string `json:"connector_execution_ref"`
	ProofSessionRef       string `json:"proof_session_ref,omitempty"`
	IntentRef             string `json:"intent_ref"`
	EffectRef             string `json:"effect_ref,omitempty"`
	ReconciliationRef     string `json:"reconciliation_ref,omitempty"`
	EvidencePackRef       string `json:"evidence_pack_ref"`
	EvidencePackHash      string `json:"evidence_pack_hash"`

	KernelTrustRootID string    `json:"kernel_trust_root_id"`
	SigningKeyRef     string    `json:"signing_key_ref"`
	ClosedBy          string    `json:"closed_by"`
	ClosedAt          time.Time `json:"closed_at"`

	ReceiptHash string `json:"receipt_hash,omitempty"`
}

func (r EffectCloseReceipt) Validate() error {
	if r.SchemaVersion != EffectCloseReceiptSchemaV1 {
		return effectCloseReceiptInvalid("unsupported schema_version")
	}
	if r.ContractVersion != EffectCloseReceiptContractV1 {
		return effectCloseReceiptInvalid("unsupported contract_version")
	}
	if r.State != EffectCloseReceiptStateClosed {
		return effectCloseReceiptInvalid("unsupported state")
	}
	for field, value := range map[string]string{
		"close_id": r.CloseID, "admission_id": r.AdmissionID, "attempt_id": r.AttemptID,
		"tenant_id": r.TenantID, "workspace_id": r.WorkspaceID, "audience": r.Audience,
		"connector_id": r.ConnectorID, "connector_version": r.ConnectorVersion,
		"connector_action": r.ConnectorAction, "connector_execution_ref": r.ConnectorExecutionRef,
		"intent_ref": r.IntentRef, "evidence_pack_ref": r.EvidencePackRef,
		"kernel_trust_root_id": r.KernelTrustRootID, "signing_key_ref": r.SigningKeyRef,
		"closed_by": r.ClosedBy,
	} {
		if !isApprovalGrantToken(value) || len(value) > 512 {
			return effectCloseReceiptInvalid(field + " is required and must be a bounded token")
		}
	}
	for field, value := range map[string]string{
		"reservation_head_hash": r.ReservationHeadHash,
		"acknowledgement_hash":  r.AcknowledgementHash,
		"idempotency_key_hash":  r.IdempotencyKeyHash,
		"effect_hash":           r.EffectHash, "response_hash": r.ResponseHash,
		"evidence_pack_hash": r.EvidencePackHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return effectCloseReceiptInvalid(field + " must be a lowercase sha256 reference")
		}
	}
	if r.ReservationSequence == 0 || r.ReservationSequence > ConnectorReleaseAuthorityMaxRevision {
		return effectCloseReceiptInvalid("reservation_sequence must be a positive JCS-safe integer")
	}
	switch r.PriorState {
	case EffectClosePriorStateStarted:
	case EffectClosePriorStateUncertain:
		if !isApprovalGrantToken(r.ReconciliationRef) || len(r.ReconciliationRef) > 512 {
			return effectCloseReceiptInvalid("UNCERTAIN closure requires a bounded reconciliation_ref")
		}
	default:
		return effectCloseReceiptInvalid("unsupported prior_state")
	}
	if r.ReconciliationRef != "" && (!isApprovalGrantToken(r.ReconciliationRef) || len(r.ReconciliationRef) > 512) {
		return effectCloseReceiptInvalid("reconciliation_ref must be a bounded token")
	}
	if r.ProofSessionRef != "" && (!isApprovalGrantToken(r.ProofSessionRef) || len(r.ProofSessionRef) > 512) {
		return effectCloseReceiptInvalid("proof_session_ref must be a bounded token")
	}
	switch r.Outcome {
	case ConnectorEffectOutcomeApplied:
		if !isApprovalGrantToken(r.EffectRef) || len(r.EffectRef) > 512 {
			return effectCloseReceiptInvalid("APPLIED requires a bounded effect_ref")
		}
	case ConnectorEffectOutcomeNotApplied:
		if r.EffectRef != "" {
			return effectCloseReceiptInvalid("NOT_APPLIED must not claim an effect_ref")
		}
	default:
		return effectCloseReceiptInvalid("unsupported outcome")
	}
	if r.ClosedAt.IsZero() || !isApprovalGrantUTC(r.ClosedAt) || !r.ClosedAt.Equal(r.ClosedAt.Truncate(time.Microsecond)) {
		return effectCloseReceiptInvalid("closed_at must use UTC microsecond precision")
	}
	if r.ReceiptHash != "" && !isApprovalGrantSHA256(r.ReceiptHash) {
		return effectCloseReceiptInvalid("receipt_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (r EffectCloseReceipt) Seal() (EffectCloseReceipt, error) {
	if err := r.Validate(); err != nil {
		return EffectCloseReceipt{}, err
	}
	r.ReceiptHash = ""
	hash, err := hashJCS(r)
	if err != nil {
		return EffectCloseReceipt{}, effectCloseReceiptInvalid("seal: " + err.Error())
	}
	r.ReceiptHash = hash
	return r, nil
}

func (r EffectCloseReceipt) ValidateIntegrity() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.ReceiptHash == "" {
		return effectCloseReceiptInvalid("receipt_hash is required")
	}
	sealed, err := r.Seal()
	if err != nil || sealed.ReceiptHash != r.ReceiptHash {
		return effectCloseReceiptInvalid("receipt integrity mismatch")
	}
	return nil
}

func (r EffectCloseReceipt) ValidateAcknowledgement(a ConnectorEffectAcknowledgement) error {
	if err := r.ValidateIntegrity(); err != nil {
		return err
	}
	if err := a.ValidateIntegrity(); err != nil {
		return err
	}
	if r.AdmissionID != a.AdmissionID || r.AttemptID != a.AttemptID ||
		r.TenantID != a.TenantID || r.WorkspaceID != a.WorkspaceID || r.Audience != a.Audience ||
		r.ConnectorID != a.ConnectorID || r.ConnectorVersion != a.ConnectorVersion ||
		r.ConnectorAction != a.ConnectorAction || r.AcknowledgementHash != a.AcknowledgementHash ||
		r.Outcome != a.Outcome || r.IdempotencyKeyHash != a.IdempotencyKeyHash ||
		r.EffectHash != a.EffectHash || r.ResponseHash != a.ResponseHash ||
		r.ConnectorExecutionRef != a.ConnectorExecutionRef || r.ProofSessionRef != a.ProofSessionRef || r.IntentRef != a.IntentRef ||
		r.EffectRef != a.EffectRef || r.ReconciliationRef != a.ReconciliationRef {
		return effectCloseReceiptInvalid("receipt does not match connector acknowledgement")
	}
	if r.ClosedAt.Add(EffectCloseMaxClockSkew).Before(a.ObservedAt) {
		return effectCloseReceiptInvalid("closed_at precedes connector observation beyond allowed clock skew")
	}
	return nil
}

func connectorEffectAcknowledgementInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrConnectorEffectAcknowledgementInvalid, message)
}

func effectCloseReceiptInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrEffectCloseReceiptInvalid, message)
}
