package approvalceremony

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

// DispatchAdmissionRequest is the data-plane binding that the Kernel admits.
// Tenant, workspace, workload subject, and audience always come from the
// verified transport identity and are intentionally absent.
type DispatchAdmissionRequest struct {
	ApprovalID         string `json:"approval_id"`
	AttemptID          string `json:"attempt_id"`
	ConsumptionHash    string `json:"consumption_hash"`
	IdempotencyKeyHash string `json:"idempotency_key_hash"`
	EffectHash         string `json:"effect_hash"`
	// ConnectorID is workload-asserted in this internal contract. It remains
	// pre-production until a source-owned policy/certification binding resolves
	// it from the approved effect rather than trusting the dispatch workload.
	ConnectorID string `json:"connector_id"`
	Action      string `json:"action"`
}

func (r DispatchAdmissionRequest) Validate() error {
	for field, value := range map[string]string{
		"approval_id": r.ApprovalID, "attempt_id": r.AttemptID, "connector_id": r.ConnectorID,
	} {
		if !validToken(value) || len(value) > 512 {
			return invalidRecord("dispatch admission " + field + " is invalid")
		}
	}
	for field, value := range map[string]string{
		"consumption_hash": r.ConsumptionHash, "idempotency_key_hash": r.IdempotencyKeyHash,
		"effect_hash": r.EffectHash,
	} {
		if !validSHA256(value) {
			return invalidRecord("dispatch admission " + field + " is invalid")
		}
	}
	switch r.Action {
	case contracts.ApprovalGrantActionInstall, contracts.ApprovalGrantActionUpgrade,
		contracts.ApprovalGrantActionUninstall, contracts.ApprovalGrantActionRollback:
	default:
		return invalidRecord("dispatch admission action is unsupported")
	}
	return nil
}

// DispatchAdmissionRecord is the immutable Kernel projection returned on an
// exact retry. Its expiry is never extended.
type DispatchAdmissionRecord struct {
	Admission          contracts.ApprovalDispatchAdmission `json:"admission"`
	SignatureAlgorithm string                              `json:"signature_algorithm"`
	Signature          string                              `json:"signature"`
	CreatedAt          time.Time                           `json:"created_at"`
	UpdatedAt          time.Time                           `json:"updated_at"`
}

func (r DispatchAdmissionRecord) Validate() error {
	if err := r.Admission.ValidateIntegrity(); err != nil {
		return err
	}
	if r.SignatureAlgorithm != GrantSignatureEd25519 || !validEd25519Signature(r.Signature) {
		return invalidRecord("dispatch admission signature is invalid")
	}
	if r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || !r.CreatedAt.Equal(r.Admission.IssuedAt) ||
		!r.UpdatedAt.Equal(r.CreatedAt) {
		return invalidRecord("dispatch admission timestamps are invalid")
	}
	return nil
}

type dispatchAdmissionSealer func(
	contracts.ApprovalGrantConsumption,
	time.Time,
) (contracts.ApprovalDispatchAdmission, string, string, error)

type dispatchAdmissionStore interface {
	claimDispatchAdmission(context.Context, ConsumerIdentity, DispatchAdmissionRequest, dispatchAdmissionSealer, time.Time) (DispatchAdmissionRecord, error)
	recoverDispatchAdmission(context.Context, ConsumerIdentity, DispatchAdmissionRequest) (DispatchAdmissionRecord, error)
}

// DispatchAdmitter owns the only capability that can mint a signed
// near-effect admission from a consumed approval grant.
type DispatchAdmitter struct {
	store    dispatchAdmissionStore
	consumer ConsumerIdentityProvider
	signer   crypto.Signer
	clock    func() time.Time
	random   io.Reader
	ttl      time.Duration
}

func NewDispatchAdmitter(store *PostgresStore, consumer ConsumerIdentityProvider, signer crypto.Signer, ttl time.Duration) (*DispatchAdmitter, error) {
	return newDispatchAdmitter(store, consumer, signer, time.Now, rand.Reader, ttl)
}

func newDispatchAdmitter(store dispatchAdmissionStore, consumer ConsumerIdentityProvider, signer crypto.Signer, clock func() time.Time, random io.Reader, ttl time.Duration) (*DispatchAdmitter, error) {
	if store == nil || consumer == nil || signer == nil || clock == nil || random == nil {
		return nil, errors.New("approval dispatch admission dependencies are required")
	}
	if ttl <= 0 || ttl > contracts.ApprovalDispatchAdmissionMaxTTL {
		return nil, errors.New("approval dispatch admission ttl must be positive and no more than one minute")
	}
	return &DispatchAdmitter{store: store, consumer: consumer, signer: signer, clock: clock, random: random, ttl: ttl}, nil
}

func (s *DispatchAdmitter) Claim(ctx context.Context, request DispatchAdmissionRequest) (DispatchAdmissionRecord, error) {
	if s == nil {
		return DispatchAdmissionRecord{}, errors.New("approval dispatch admitter is not initialized")
	}
	if err := request.Validate(); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return DispatchAdmissionRecord{}, err
	}
	seal := func(consumption contracts.ApprovalGrantConsumption, issuedAt time.Time) (contracts.ApprovalDispatchAdmission, string, string, error) {
		if consumption.ApprovalID != request.ApprovalID || consumption.ConsumptionHash != request.ConsumptionHash ||
			consumption.EffectHash != request.EffectHash || consumption.Action != request.Action ||
			consumption.TenantID != identity.TenantID || consumption.WorkspaceID != identity.WorkspaceID ||
			consumption.Audience != identity.Audience || consumption.ConsumedBy != identity.Subject {
			return contracts.ApprovalDispatchAdmission{}, "", "", ErrTransitionConflict
		}
		expiresAt := issuedAt.Add(s.ttl)
		if expiresAt.After(consumption.GrantExpiresAt) {
			expiresAt = consumption.GrantExpiresAt
		}
		if !expiresAt.After(issuedAt) {
			return contracts.ApprovalDispatchAdmission{}, "", "", ErrTransitionConflict
		}
		admissionID, randomErr := s.randomToken("dispatch-admission", 16)
		if randomErr != nil {
			return contracts.ApprovalDispatchAdmission{}, "", "", randomErr
		}
		admission, sealErr := (contracts.ApprovalDispatchAdmission{
			SchemaVersion:   contracts.ApprovalDispatchAdmissionSchemaV1,
			ContractVersion: contracts.ApprovalDispatchAdmissionContractV1,
			Coverage:        contracts.ApprovalDispatchAdmissionCoverageV1,
			AdmissionID:     admissionID, AttemptID: request.AttemptID,
			State:      contracts.ApprovalDispatchAdmissionStateV1,
			ApprovalID: consumption.ApprovalID, GrantID: consumption.GrantID,
			GrantHash: consumption.GrantHash, ConsumptionHash: consumption.ConsumptionHash,
			TenantID: consumption.TenantID, WorkspaceID: consumption.WorkspaceID,
			Audience: consumption.Audience, AdmittedBy: identity.Subject,
			IdempotencyKeyHash: request.IdempotencyKeyHash, EffectHash: request.EffectHash,
			ConnectorID: request.ConnectorID, Action: request.Action,
			KernelTrustRootID: consumption.KernelTrustRootID, SigningKeyRef: consumption.SigningKeyRef,
			IssuedAt: issuedAt, ExpiresAt: expiresAt,
		}).Seal()
		if sealErr != nil {
			return contracts.ApprovalDispatchAdmission{}, "", "", fmt.Errorf("seal dispatch admission: %w", sealErr)
		}
		if err := admission.ValidateConsumption(consumption); err != nil {
			return contracts.ApprovalDispatchAdmission{}, "", "", err
		}
		signature, signErr := SignApprovalDispatchAdmission(admission, s.signer)
		if signErr != nil {
			return contracts.ApprovalDispatchAdmission{}, "", "", signErr
		}
		return admission, GrantSignatureEd25519, signature, nil
	}
	return s.store.claimDispatchAdmission(ctx, identity, request, seal, s.now())
}

func (s *DispatchAdmitter) Recover(ctx context.Context, request DispatchAdmissionRequest) (DispatchAdmissionRecord, error) {
	if s == nil {
		return DispatchAdmissionRecord{}, errors.New("approval dispatch admitter is not initialized")
	}
	if err := request.Validate(); err != nil {
		return DispatchAdmissionRecord{}, err
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return DispatchAdmissionRecord{}, err
	}
	return s.store.recoverDispatchAdmission(ctx, identity, request)
}

func (s *DispatchAdmitter) now() time.Time {
	return s.clock().UTC().Truncate(time.Microsecond)
}

func (s *DispatchAdmitter) randomToken(prefix string, size int) (string, error) {
	raw := make([]byte, size)
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return "", fmt.Errorf("generate dispatch admission id: %w", err)
	}
	return prefix + "-" + hex.EncodeToString(raw), nil
}
