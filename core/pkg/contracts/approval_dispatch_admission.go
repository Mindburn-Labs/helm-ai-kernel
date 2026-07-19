package contracts

import (
	"errors"
	"fmt"
	"time"
)

const (
	ApprovalDispatchAdmissionSchemaV1   = "approval-dispatch-admission.v1"
	ApprovalDispatchAdmissionContractV1 = "2026-07-17"
	ApprovalDispatchAdmissionCoverageV1 = "new_governed_dispatches_only"
	ApprovalDispatchAdmissionStateV1    = "NOT_STARTED"
	ApprovalDispatchAdmissionMaxTTL     = time.Minute
)

var ErrApprovalDispatchAdmissionInactive = errors.New("approval dispatch admission inactive")

// ApprovalDispatchAdmission is the Kernel-signed linearization record required
// immediately before a data plane may move one consumed approval grant into
// DISPATCHING. Admission issuance is serialized with scoped FENCE; it is not a
// generic connector permit and does not claim to cancel already admitted work.
type ApprovalDispatchAdmission struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`
	Coverage        string `json:"coverage"`

	AdmissionID string `json:"admission_id"`
	AttemptID   string `json:"attempt_id"`
	State       string `json:"state"`

	ApprovalID      string `json:"approval_id"`
	GrantID         string `json:"grant_id"`
	GrantHash       string `json:"grant_hash"`
	ConsumptionHash string `json:"consumption_hash"`

	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Audience    string `json:"audience"`
	AdmittedBy  string `json:"admitted_by"`

	IdempotencyKeyHash string `json:"idempotency_key_hash"`
	EffectHash         string `json:"effect_hash"`
	ConnectorID        string `json:"connector_id"`
	Action             string `json:"action"`

	KernelTrustRootID string `json:"kernel_trust_root_id"`
	SigningKeyRef     string `json:"signing_key_ref"`

	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`

	AdmissionHash string `json:"admission_hash,omitempty"`
}

func (a ApprovalDispatchAdmission) Validate() error {
	if a.SchemaVersion != ApprovalDispatchAdmissionSchemaV1 {
		return approvalDispatchAdmissionInvalid("unsupported schema_version")
	}
	if a.ContractVersion != ApprovalDispatchAdmissionContractV1 {
		return approvalDispatchAdmissionInvalid("unsupported contract_version")
	}
	if a.Coverage != ApprovalDispatchAdmissionCoverageV1 {
		return approvalDispatchAdmissionInvalid("unsupported coverage")
	}
	if a.State != ApprovalDispatchAdmissionStateV1 {
		return approvalDispatchAdmissionInvalid("unsupported state")
	}
	for field, value := range map[string]string{
		"admission_id": a.AdmissionID, "attempt_id": a.AttemptID,
		"approval_id": a.ApprovalID, "grant_id": a.GrantID,
		"tenant_id": a.TenantID, "workspace_id": a.WorkspaceID,
		"audience": a.Audience, "admitted_by": a.AdmittedBy,
		"connector_id": a.ConnectorID, "kernel_trust_root_id": a.KernelTrustRootID,
		"signing_key_ref": a.SigningKeyRef,
	} {
		if !isApprovalDispatchAdmissionToken(value) {
			return approvalDispatchAdmissionInvalid(field + " is required and must not contain whitespace")
		}
	}
	for field, value := range map[string]string{
		"grant_hash": a.GrantHash, "consumption_hash": a.ConsumptionHash,
		"idempotency_key_hash": a.IdempotencyKeyHash, "effect_hash": a.EffectHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return approvalDispatchAdmissionInvalid(field + " must be a lowercase sha256 reference")
		}
	}
	switch a.Action {
	case ApprovalGrantActionInstall, ApprovalGrantActionUpgrade,
		ApprovalGrantActionUninstall, ApprovalGrantActionRollback:
	default:
		return approvalDispatchAdmissionInvalid("unsupported action")
	}
	if a.IssuedAt.IsZero() || a.ExpiresAt.IsZero() ||
		!isApprovalGrantUTC(a.IssuedAt) || !isApprovalGrantUTC(a.ExpiresAt) {
		return approvalDispatchAdmissionInvalid("issued_at and expires_at must use UTC")
	}
	if !a.ExpiresAt.After(a.IssuedAt) || a.ExpiresAt.Sub(a.IssuedAt) > ApprovalDispatchAdmissionMaxTTL {
		return approvalDispatchAdmissionInvalid("expires_at must be after issued_at and within one minute")
	}
	if a.AdmissionHash != "" && !isApprovalGrantSHA256(a.AdmissionHash) {
		return approvalDispatchAdmissionInvalid("admission_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (a ApprovalDispatchAdmission) Seal() (ApprovalDispatchAdmission, error) {
	if err := a.Validate(); err != nil {
		return ApprovalDispatchAdmission{}, err
	}
	a.AdmissionHash = ""
	hash, err := hashJCS(a)
	if err != nil {
		return ApprovalDispatchAdmission{}, fmt.Errorf("%w: seal dispatch admission: %v", ErrApprovalGrantIntegrity, err)
	}
	a.AdmissionHash = hash
	return a, nil
}

// ValidateIntegrity verifies the self-hash without requiring the separately
// signed consumption record. Callers that hold the consumption must use
// ValidateConsumption as the stronger binding check.
func (a ApprovalDispatchAdmission) ValidateIntegrity() error {
	if err := a.Validate(); err != nil {
		return err
	}
	if a.AdmissionHash == "" {
		return approvalDispatchAdmissionInvalid("admission_hash is required")
	}
	sealed, err := a.Seal()
	if err != nil || sealed.AdmissionHash != a.AdmissionHash {
		return approvalDispatchAdmissionInvalid("admission integrity mismatch")
	}
	return nil
}

// ValidateAt checks deterministic integrity and the half-open admission
// lifetime [issued_at, expires_at). It does not verify the Kernel signature or
// prove durable attempt state; effect boundaries must perform all three gates.
func (a ApprovalDispatchAdmission) ValidateAt(now time.Time) error {
	if err := a.ValidateIntegrity(); err != nil {
		return err
	}
	if now.Before(a.IssuedAt) {
		return fmt.Errorf("%w: admission is not yet active", ErrApprovalDispatchAdmissionInactive)
	}
	if !now.Before(a.ExpiresAt) {
		return fmt.Errorf("%w: admission is expired", ErrApprovalDispatchAdmissionInactive)
	}
	return nil
}

// ValidateConsumption proves that an admission is bound to the exact signed
// consumption it advances toward a connector effect.
func (a ApprovalDispatchAdmission) ValidateConsumption(consumption ApprovalGrantConsumption) error {
	if err := a.ValidateIntegrity(); err != nil {
		return err
	}
	if err := consumption.Validate(); err != nil || consumption.ConsumptionHash == "" {
		return approvalDispatchAdmissionInvalid("consumption is invalid")
	}
	sealedConsumption, err := consumption.Seal()
	if err != nil || sealedConsumption.ConsumptionHash != consumption.ConsumptionHash {
		return approvalDispatchAdmissionInvalid("consumption integrity mismatch")
	}
	if a.ApprovalID != consumption.ApprovalID || a.GrantID != consumption.GrantID ||
		a.GrantHash != consumption.GrantHash || a.ConsumptionHash != consumption.ConsumptionHash ||
		a.TenantID != consumption.TenantID || a.WorkspaceID != consumption.WorkspaceID ||
		a.Audience != consumption.Audience || a.AdmittedBy != consumption.ConsumedBy ||
		a.EffectHash != consumption.EffectHash || a.Action != consumption.Action ||
		a.KernelTrustRootID != consumption.KernelTrustRootID || a.SigningKeyRef != consumption.SigningKeyRef {
		return approvalDispatchAdmissionInvalid("admission does not match the signed consumption")
	}
	if a.IssuedAt.Before(consumption.ConsumedAt) || a.IssuedAt.Before(consumption.GrantIssuedAt) ||
		a.ExpiresAt.After(consumption.GrantExpiresAt) {
		return approvalDispatchAdmissionInvalid("admission is outside the consumed grant lifetime")
	}
	return nil
}

func approvalDispatchAdmissionInvalid(message string) error {
	return fmt.Errorf("%w: dispatch admission: %s", ErrApprovalGrantIntegrity, message)
}

func isApprovalDispatchAdmissionToken(value string) bool {
	return len(value) <= 512 && isApprovalGrantConsumptionToken(value)
}
