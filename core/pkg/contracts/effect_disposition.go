package contracts

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	EffectDispositionCommandSchemaV1   = "effect-disposition-command.v1"
	EffectDispositionCommandContractV1 = "2026-07-18"
	EffectDispositionAlgorithmV1       = "ed25519"

	EffectDispositionActionHold              = "HOLD"
	EffectDispositionActionReconcileSource   = "RECONCILE_SOURCE"
	EffectDispositionActionRequestCancel     = "REQUEST_CANCEL"
	EffectDispositionActionRequestCompensate = "REQUEST_COMPENSATE"

	EffectDispositionReceiptSchemaV1           = "effect-disposition-receipt.v1"
	EffectDispositionReceiptContractV1         = "2026-07-18"
	EffectDispositionReceiptStateAccepted      = "ACCEPTED"
	EffectDispositionExecutionAuthorityNone    = "NONE"
	EffectDispositionMaxCommandLifetime        = 10 * time.Minute
	EffectDispositionMaxCommandFutureClockSkew = time.Minute
)

var (
	ErrEffectDispositionCommandInvalid = errors.New("effect disposition command invalid")
	ErrEffectDispositionReceiptInvalid = errors.New("effect disposition receipt invalid")
)

// EffectDispositionCommand is a Control Plane instruction about already-active
// connector work. It never grants permission to execute cancellation,
// compensation, or any other external effect.
type EffectDispositionCommand struct {
	SchemaVersion   string `json:"schema_version"`
	ContractVersion string `json:"contract_version"`

	CommandID           string `json:"command_id"`
	DispositionSequence uint64 `json:"disposition_sequence"`
	PreviousReceiptHash string `json:"previous_receipt_hash,omitempty"`

	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Audience    string `json:"audience"`

	FenceCommandID   string `json:"fence_command_id"`
	FenceCommandHash string `json:"fence_command_hash"`
	FenceEpoch       uint64 `json:"fence_epoch"`
	FenceReceiptHash string `json:"fence_receipt_hash"`

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

	Action         string `json:"action"`
	DispositionRef string `json:"disposition_ref"`
	ActorID        string `json:"actor_id"`
	Reason         string `json:"reason"`

	AuthorityID   string    `json:"authority_id"`
	SigningKeyRef string    `json:"signing_key_ref"`
	Algorithm     string    `json:"algorithm"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`

	CommandHash string `json:"command_hash,omitempty"`
}

type EffectDispositionCommandEnvelope struct {
	Command   EffectDispositionCommand `json:"command"`
	Signature string                   `json:"signature"`
}

func (c EffectDispositionCommand) Validate() error {
	if c.SchemaVersion != EffectDispositionCommandSchemaV1 || c.ContractVersion != EffectDispositionCommandContractV1 {
		return effectDispositionCommandInvalid("unsupported contract")
	}
	if c.Algorithm != EffectDispositionAlgorithmV1 {
		return effectDispositionCommandInvalid("unsupported algorithm")
	}
	for field, value := range map[string]string{
		"command_id": c.CommandID, "tenant_id": c.TenantID, "workspace_id": c.WorkspaceID,
		"audience": c.Audience, "fence_command_id": c.FenceCommandID,
		"admission_id": c.AdmissionID, "attempt_id": c.AttemptID,
		"connector_id": c.ConnectorID, "connector_version": c.ConnectorVersion,
		"connector_action": c.ConnectorAction, "connector_execution_ref": c.ConnectorExecutionRef,
		"intent_ref": c.IntentRef, "disposition_ref": c.DispositionRef,
		"actor_id": c.ActorID, "authority_id": c.AuthorityID,
		"signing_key_ref": c.SigningKeyRef,
	} {
		if !isApprovalGrantToken(value) || len(value) > 512 {
			return effectDispositionCommandInvalid(field + " is required and must be a bounded token")
		}
	}
	if c.Reason == "" || c.Reason != strings.TrimSpace(c.Reason) || len(c.Reason) > 2048 {
		return effectDispositionCommandInvalid("reason is required and must be a bounded string without outer whitespace")
	}
	for field, value := range map[string]string{
		"fence_command_hash": c.FenceCommandHash, "fence_receipt_hash": c.FenceReceiptHash,
		"reservation_head_hash": c.ReservationHeadHash, "idempotency_key_hash": c.IdempotencyKeyHash,
		"effect_hash": c.EffectHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return effectDispositionCommandInvalid(field + " must be a lowercase sha256 reference")
		}
	}
	if c.DispositionSequence == 0 || c.DispositionSequence > ConnectorReleaseAuthorityMaxRevision ||
		c.ReservationSequence == 0 || c.ReservationSequence > ConnectorReleaseAuthorityMaxRevision ||
		c.FenceEpoch == 0 || c.FenceEpoch > ConnectorReleaseAuthorityMaxRevision {
		return effectDispositionCommandInvalid("sequence and epoch values must be positive JCS-safe integers")
	}
	if c.DispositionSequence == 1 {
		if c.PreviousReceiptHash != "" {
			return effectDispositionCommandInvalid("first disposition must not claim previous_receipt_hash")
		}
	} else if !isApprovalGrantSHA256(c.PreviousReceiptHash) {
		return effectDispositionCommandInvalid("successor disposition requires previous_receipt_hash")
	}
	switch c.ReservationState {
	case EffectClosePriorStateStarted, EffectClosePriorStateUncertain:
	default:
		return effectDispositionCommandInvalid("reservation_state must be STARTED or UNCERTAIN")
	}
	switch c.Action {
	case EffectDispositionActionHold, EffectDispositionActionReconcileSource,
		EffectDispositionActionRequestCancel, EffectDispositionActionRequestCompensate:
	default:
		return effectDispositionCommandInvalid("unsupported action")
	}
	for field, value := range map[string]string{
		"proof_session_ref": c.ProofSessionRef, "effect_ref": c.EffectRef,
	} {
		if value != "" && (!isApprovalGrantToken(value) || len(value) > 512) {
			return effectDispositionCommandInvalid(field + " must be a bounded token")
		}
	}
	if c.IssuedAt.IsZero() || c.ExpiresAt.IsZero() || !isApprovalGrantUTC(c.IssuedAt) || !isApprovalGrantUTC(c.ExpiresAt) ||
		!c.IssuedAt.Equal(c.IssuedAt.Truncate(time.Microsecond)) || !c.ExpiresAt.Equal(c.ExpiresAt.Truncate(time.Microsecond)) ||
		!c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > EffectDispositionMaxCommandLifetime {
		return effectDispositionCommandInvalid("command timestamps must be UTC microsecond precision with a bounded lifetime")
	}
	if c.CommandHash != "" && !isApprovalGrantSHA256(c.CommandHash) {
		return effectDispositionCommandInvalid("command_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (c EffectDispositionCommand) Seal() (EffectDispositionCommand, error) {
	if err := c.Validate(); err != nil {
		return EffectDispositionCommand{}, err
	}
	c.CommandHash = ""
	hash, err := hashJCS(c)
	if err != nil {
		return EffectDispositionCommand{}, effectDispositionCommandInvalid("seal: " + err.Error())
	}
	c.CommandHash = hash
	return c, nil
}

func (c EffectDispositionCommand) ValidateIntegrity() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.CommandHash == "" {
		return effectDispositionCommandInvalid("command_hash is required")
	}
	sealed, err := c.Seal()
	if err != nil || sealed.CommandHash != c.CommandHash {
		return effectDispositionCommandInvalid("command integrity mismatch")
	}
	return nil
}

func (e EffectDispositionCommandEnvelope) Validate() error {
	if err := e.Command.ValidateIntegrity(); err != nil {
		return err
	}
	raw, err := hex.DecodeString(e.Signature)
	if err != nil || len(raw) != 64 || hex.EncodeToString(raw) != e.Signature {
		return effectDispositionCommandInvalid("signature must be canonical lowercase Ed25519 hex")
	}
	return nil
}

// EffectDispositionReceipt is Kernel acknowledgement that a command was
// durably recorded against an exact active reservation and FENCE. Its explicit
// NONE authority prevents an acknowledgement from being treated as an effect
// permit.
type EffectDispositionReceipt struct {
	SchemaVersion      string `json:"schema_version"`
	ContractVersion    string `json:"contract_version"`
	ReceiptID          string `json:"receipt_id"`
	State              string `json:"state"`
	ExecutionAuthority string `json:"execution_authority"`

	CommandID           string `json:"command_id"`
	CommandHash         string `json:"command_hash"`
	DispositionSequence uint64 `json:"disposition_sequence"`
	PreviousReceiptHash string `json:"previous_receipt_hash,omitempty"`

	TenantID    string `json:"tenant_id"`
	WorkspaceID string `json:"workspace_id"`
	Audience    string `json:"audience"`

	FenceCommandID   string `json:"fence_command_id"`
	FenceCommandHash string `json:"fence_command_hash"`
	FenceEpoch       uint64 `json:"fence_epoch"`
	FenceReceiptHash string `json:"fence_receipt_hash"`

	AdmissionID         string `json:"admission_id"`
	ReservationSequence uint64 `json:"reservation_sequence"`
	ReservationHeadHash string `json:"reservation_head_hash"`
	ReservationState    string `json:"reservation_state"`
	Action              string `json:"action"`
	DispositionRef      string `json:"disposition_ref"`

	KernelTrustRootID string    `json:"kernel_trust_root_id"`
	SigningKeyRef     string    `json:"signing_key_ref"`
	AcceptedBy        string    `json:"accepted_by"`
	AcceptedAt        time.Time `json:"accepted_at"`

	ReceiptHash string `json:"receipt_hash,omitempty"`
}

func (r EffectDispositionReceipt) Validate() error {
	if r.SchemaVersion != EffectDispositionReceiptSchemaV1 || r.ContractVersion != EffectDispositionReceiptContractV1 ||
		r.State != EffectDispositionReceiptStateAccepted || r.ExecutionAuthority != EffectDispositionExecutionAuthorityNone {
		return effectDispositionReceiptInvalid("unsupported contract state or execution authority")
	}
	for field, value := range map[string]string{
		"receipt_id": r.ReceiptID, "command_id": r.CommandID, "tenant_id": r.TenantID,
		"workspace_id": r.WorkspaceID, "audience": r.Audience, "fence_command_id": r.FenceCommandID,
		"admission_id": r.AdmissionID, "reservation_state": r.ReservationState,
		"action": r.Action, "disposition_ref": r.DispositionRef,
		"kernel_trust_root_id": r.KernelTrustRootID, "signing_key_ref": r.SigningKeyRef,
		"accepted_by": r.AcceptedBy,
	} {
		if !isApprovalGrantToken(value) || len(value) > 512 {
			return effectDispositionReceiptInvalid(field + " is required and must be a bounded token")
		}
	}
	for field, value := range map[string]string{
		"command_hash": r.CommandHash, "fence_command_hash": r.FenceCommandHash,
		"fence_receipt_hash": r.FenceReceiptHash, "reservation_head_hash": r.ReservationHeadHash,
	} {
		if !isApprovalGrantSHA256(value) {
			return effectDispositionReceiptInvalid(field + " must be a lowercase sha256 reference")
		}
	}
	if r.DispositionSequence == 0 || r.DispositionSequence > ConnectorReleaseAuthorityMaxRevision ||
		r.ReservationSequence == 0 || r.ReservationSequence > ConnectorReleaseAuthorityMaxRevision ||
		r.FenceEpoch == 0 || r.FenceEpoch > ConnectorReleaseAuthorityMaxRevision {
		return effectDispositionReceiptInvalid("sequence and epoch values must be positive JCS-safe integers")
	}
	if r.DispositionSequence == 1 {
		if r.PreviousReceiptHash != "" {
			return effectDispositionReceiptInvalid("first receipt must not claim previous_receipt_hash")
		}
	} else if !isApprovalGrantSHA256(r.PreviousReceiptHash) {
		return effectDispositionReceiptInvalid("successor receipt requires previous_receipt_hash")
	}
	switch r.ReservationState {
	case EffectClosePriorStateStarted, EffectClosePriorStateUncertain:
	default:
		return effectDispositionReceiptInvalid("reservation_state must be STARTED or UNCERTAIN")
	}
	switch r.Action {
	case EffectDispositionActionHold, EffectDispositionActionReconcileSource,
		EffectDispositionActionRequestCancel, EffectDispositionActionRequestCompensate:
	default:
		return effectDispositionReceiptInvalid("unsupported action")
	}
	if r.AcceptedAt.IsZero() || !isApprovalGrantUTC(r.AcceptedAt) || !r.AcceptedAt.Equal(r.AcceptedAt.Truncate(time.Microsecond)) {
		return effectDispositionReceiptInvalid("accepted_at must use UTC microsecond precision")
	}
	if r.ReceiptHash != "" && !isApprovalGrantSHA256(r.ReceiptHash) {
		return effectDispositionReceiptInvalid("receipt_hash must be a lowercase sha256 reference")
	}
	return nil
}

func (r EffectDispositionReceipt) Seal() (EffectDispositionReceipt, error) {
	if err := r.Validate(); err != nil {
		return EffectDispositionReceipt{}, err
	}
	r.ReceiptHash = ""
	hash, err := hashJCS(r)
	if err != nil {
		return EffectDispositionReceipt{}, effectDispositionReceiptInvalid("seal: " + err.Error())
	}
	r.ReceiptHash = hash
	return r, nil
}

func (r EffectDispositionReceipt) ValidateIntegrity() error {
	if err := r.Validate(); err != nil {
		return err
	}
	if r.ReceiptHash == "" {
		return effectDispositionReceiptInvalid("receipt_hash is required")
	}
	sealed, err := r.Seal()
	if err != nil || sealed.ReceiptHash != r.ReceiptHash {
		return effectDispositionReceiptInvalid("receipt integrity mismatch")
	}
	return nil
}

func (r EffectDispositionReceipt) ValidateCommand(c EffectDispositionCommand) error {
	if err := r.ValidateIntegrity(); err != nil {
		return err
	}
	if err := c.ValidateIntegrity(); err != nil {
		return err
	}
	if r.CommandID != c.CommandID || r.CommandHash != c.CommandHash ||
		r.DispositionSequence != c.DispositionSequence || r.PreviousReceiptHash != c.PreviousReceiptHash ||
		r.TenantID != c.TenantID || r.WorkspaceID != c.WorkspaceID || r.Audience != c.Audience ||
		r.FenceCommandID != c.FenceCommandID || r.FenceCommandHash != c.FenceCommandHash ||
		r.FenceEpoch != c.FenceEpoch || r.FenceReceiptHash != c.FenceReceiptHash ||
		r.AdmissionID != c.AdmissionID || r.ReservationSequence != c.ReservationSequence ||
		r.ReservationHeadHash != c.ReservationHeadHash || r.ReservationState != c.ReservationState ||
		r.Action != c.Action || r.DispositionRef != c.DispositionRef {
		return effectDispositionReceiptInvalid("receipt does not match disposition command")
	}
	return nil
}

func effectDispositionCommandInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrEffectDispositionCommandInvalid, message)
}

func effectDispositionReceiptInvalid(message string) error {
	return fmt.Errorf("%w: %s", ErrEffectDispositionReceiptInvalid, message)
}
