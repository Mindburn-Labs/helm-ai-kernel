package approvalceremony

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/kernel"
	connectorregistry "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/registry/connectors"
)

var (
	ErrEffectDispositionConflict      = errors.New("effect disposition conflicts with durable authority state")
	ErrEffectDispositionTerminal      = errors.New("effect disposition targets a non-active reservation")
	ErrEffectDispositionRequiresFence = errors.New("effect disposition requires an active matching FENCE")
)

type EffectDispositionRecord struct {
	Command            contracts.EffectDispositionCommandEnvelope `json:"command"`
	Fence              kernel.FenceState                          `json:"fence"`
	Receipt            contracts.EffectDispositionReceipt         `json:"receipt"`
	SignatureAlgorithm string                                     `json:"signature_algorithm"`
	Signature          string                                     `json:"signature"`
	CreatedAt          time.Time                                  `json:"created_at"`
}

func (r EffectDispositionRecord) Validate() error {
	if err := r.Command.Validate(); err != nil {
		return err
	}
	if err := r.Receipt.ValidateCommand(r.Command.Command); err != nil {
		return err
	}
	command := r.Command.Command
	if r.Fence.TenantID != command.TenantID || r.Fence.WorkspaceID != command.WorkspaceID ||
		r.Fence.CommandID != command.FenceCommandID || r.Fence.CommandHash != command.FenceCommandHash ||
		r.Fence.Epoch != command.FenceEpoch || r.Fence.ReceiptHash != command.FenceReceiptHash {
		return ErrEffectDispositionConflict
	}
	fencePayload, err := r.Fence.AcknowledgementPayload()
	if err != nil {
		return ErrEffectDispositionConflict
	}
	fenceSum := sha256.Sum256(fencePayload)
	if r.Fence.ReceiptHash != "sha256:"+hex.EncodeToString(fenceSum[:]) {
		return ErrEffectDispositionConflict
	}
	if r.SignatureAlgorithm != GrantSignatureEd25519 || !validEd25519Signature(r.Signature) ||
		r.CreatedAt.IsZero() || !r.CreatedAt.Equal(r.Receipt.AcceptedAt) {
		return invalidRecord("effect disposition receipt signature or timestamp is invalid")
	}
	return nil
}

// EffectDispositionService records Control Plane instructions for already
// active work. Acceptance carries no effect authority. A Data Plane must use a
// separate governed path for any cancellation or compensation attempt.
type EffectDispositionService struct {
	store              *PostgresStore
	consumer           ConsumerIdentityProvider
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore
	commandVerifier    EffectDispositionCommandVerifier
	signer             crypto.Signer
}

func NewEffectDispositionService(
	store *PostgresStore,
	consumer ConsumerIdentityProvider,
	releaseAuthorities *connectorregistry.PostgresReleaseAuthorityStore,
	commandVerifier EffectDispositionCommandVerifier,
	signer crypto.Signer,
) (*EffectDispositionService, error) {
	if store == nil || consumer == nil || releaseAuthorities == nil || commandVerifier == nil || signer == nil {
		return nil, errors.New("effect disposition dependencies are required")
	}
	return &EffectDispositionService{
		store: store, consumer: consumer, releaseAuthorities: releaseAuthorities,
		commandVerifier: commandVerifier, signer: signer,
	}, nil
}

func (s *EffectDispositionService) Record(
	ctx context.Context,
	command contracts.EffectDispositionCommandEnvelope,
) (EffectDispositionRecord, error) {
	if s == nil || s.store == nil || s.commandVerifier == nil || s.signer == nil {
		return EffectDispositionRecord{}, errors.New("effect disposition service is not initialized")
	}
	// Lenient preflight only: the store enforces an enabled key for a genuinely
	// new disposition and tolerates a since-disabled key when replaying an
	// already-recorded command, so idempotent retries survive a key rotation.
	if err := s.commandVerifier.VerifyStoredEnvelope(command); err != nil {
		return EffectDispositionRecord{}, err
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return EffectDispositionRecord{}, err
	}
	return s.store.recordEffectDisposition(
		ctx, identity, command, s.releaseAuthorities, s.commandVerifier, s.signer,
	)
}

func (s *EffectDispositionService) Recover(ctx context.Context, commandID string) (EffectDispositionRecord, error) {
	if s == nil || s.store == nil || s.commandVerifier == nil {
		return EffectDispositionRecord{}, errors.New("effect disposition service is not initialized")
	}
	if !validToken(commandID) || len(commandID) > 512 {
		return EffectDispositionRecord{}, ErrEffectDispositionConflict
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return EffectDispositionRecord{}, err
	}
	return s.store.recoverEffectDisposition(ctx, identity, commandID, s.releaseAuthorities, s.commandVerifier)
}

func (s *EffectDispositionService) ListForEffect(ctx context.Context, admissionID string) ([]EffectDispositionRecord, error) {
	if s == nil || s.store == nil || s.commandVerifier == nil {
		return nil, errors.New("effect disposition service is not initialized")
	}
	if !validToken(admissionID) || len(admissionID) > 512 {
		return nil, ErrEffectDispositionConflict
	}
	identity, err := verifiedConsumerIdentity(ctx, s.consumer)
	if err != nil {
		return nil, err
	}
	return s.store.listEffectDispositions(ctx, identity, admissionID, s.releaseAuthorities, s.commandVerifier)
}
