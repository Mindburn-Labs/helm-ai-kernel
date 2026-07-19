package approvalceremony

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type consumerIdentityContextKey struct{}

// WithConsumerIdentity installs an identity that has already been verified by
// the transport boundary. HTTP payloads and caller-controlled headers must
// never be used to construct this value.
func WithConsumerIdentity(ctx context.Context, identity ConsumerIdentity) context.Context {
	return context.WithValue(ctx, consumerIdentityContextKey{}, identity)
}

// ContextConsumerIdentityProvider reads only the verified transport identity
// installed with WithConsumerIdentity.
type ContextConsumerIdentityProvider struct{}

func (ContextConsumerIdentityProvider) LoadConsumerIdentity(ctx context.Context) (ConsumerIdentity, error) {
	identity, ok := ctx.Value(consumerIdentityContextKey{}).(ConsumerIdentity)
	if !ok {
		return ConsumerIdentity{}, errors.New("verified workload identity is absent")
	}
	return identity, nil
}

// GrantConsumer is the narrow execution-boundary capability that consumes or
// recovers a signed pack-lifecycle ApprovalGrant. It cannot create challenges,
// verify human quorum, issue grants, or promote a grant into a generic effect
// permit.
type GrantConsumer struct {
	store    ceremonyStore
	consumer ConsumerIdentityProvider
	signer   crypto.Signer
	clock    func() time.Time
}

func NewGrantConsumer(store *PostgresStore, consumer ConsumerIdentityProvider, signer crypto.Signer) (*GrantConsumer, error) {
	return newGrantConsumer(store, consumer, signer, time.Now)
}

func newGrantConsumer(store ceremonyStore, consumer ConsumerIdentityProvider, signer crypto.Signer, clock func() time.Time) (*GrantConsumer, error) {
	if store == nil || consumer == nil || signer == nil || clock == nil {
		return nil, errors.New("approval grant consumer dependencies are required")
	}
	return &GrantConsumer{store: store, consumer: consumer, signer: signer, clock: clock}, nil
}

func (s *GrantConsumer) ConsumeGrant(ctx context.Context, approvalID, grantID, grantHash, nonce string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("approval grant consumer is not initialized")
	}
	return consumeGrant(ctx, s.store, s.consumer, s.signer, s.now(), approvalID, grantID, grantHash, nonce)
}

func (s *GrantConsumer) RecoverGrantConsumption(ctx context.Context, approvalID, grantID, grantHash, nonce string) (Record, error) {
	if s == nil {
		return Record{}, errors.New("approval grant consumer is not initialized")
	}
	return recoverGrantConsumption(ctx, s.store, s.consumer, s.now(), approvalID, grantID, grantHash, nonce)
}

func (s *GrantConsumer) now() time.Time {
	return s.clock().UTC().Truncate(time.Microsecond)
}

func consumeGrant(ctx context.Context, store ceremonyStore, consumer ConsumerIdentityProvider, signer crypto.Signer, now time.Time, approvalID, grantID, grantHash, nonce string) (Record, error) {
	identity, err := verifiedConsumerIdentity(ctx, consumer)
	if err != nil {
		return Record{}, err
	}
	record, err := store.get(ctx, identity.TenantID, identity.WorkspaceID, approvalID)
	if err != nil {
		return Record{}, err
	}
	if record.State != StateGrantIssued || record.Grant == nil ||
		record.Grant.GrantID != grantID || record.Grant.GrantHash != grantHash || record.Grant.Nonce != nonce {
		return Record{}, ErrTransitionConflict
	}
	if record.Grant.Audience != identity.Audience {
		return Record{}, fmt.Errorf("%w: signed grant workload scope mismatch", ErrConsumerUnavailable)
	}
	if err := record.Grant.ValidateAt(now); err != nil {
		return Record{}, fmt.Errorf("%w: signed grant is inactive: %v", ErrTransitionConflict, err)
	}
	sealConsumption := func(grant contracts.ApprovalGrant, consumedAt time.Time) (contracts.ApprovalGrantConsumption, string, string, error) {
		if grant.GrantID != grantID || grant.GrantHash != grantHash || grant.Nonce != nonce ||
			grant.TenantID != identity.TenantID || grant.WorkspaceID != identity.WorkspaceID || grant.Audience != identity.Audience {
			return contracts.ApprovalGrantConsumption{}, "", "", ErrTransitionConflict
		}
		if err := grant.ValidateAt(consumedAt); err != nil {
			return contracts.ApprovalGrantConsumption{}, "", "", fmt.Errorf("%w: signed grant is inactive: %v", ErrTransitionConflict, err)
		}
		consumption, err := (contracts.ApprovalGrantConsumption{
			SchemaVersion: contracts.ApprovalGrantConsumptionSchemaV1, ContractVersion: contracts.ApprovalGrantConsumptionContractV1,
			ApprovalID: grant.ApprovalID, GrantID: grant.GrantID, GrantHash: grant.GrantHash,
			TenantID: grant.TenantID, WorkspaceID: grant.WorkspaceID, Audience: grant.Audience, ConsumedBy: identity.Subject,
			PackID: grant.PackID, PackVersion: grant.PackVersion, PackManifestHash: grant.PackManifestHash, Action: grant.Action,
			IntentHash: grant.IntentHash, EffectHash: grant.EffectHash, PlanHash: grant.PlanHash,
			PolicyVersion: grant.PolicyVersion, PolicyEpoch: grant.PolicyEpoch, PolicyHash: grant.PolicyHash,
			ServerIdentity: grant.ServerIdentity, KernelTrustRootID: grant.KernelTrustRootID, SigningKeyRef: grant.SigningKeyRef,
			GrantIssuedAt: grant.IssuedAt, GrantExpiresAt: grant.ExpiresAt, ConsumedAt: consumedAt,
		}).Seal()
		if err != nil {
			return contracts.ApprovalGrantConsumption{}, "", "", fmt.Errorf("seal approval grant consumption: %w", err)
		}
		signature, err := SignApprovalGrantConsumption(consumption, signer)
		if err != nil {
			return contracts.ApprovalGrantConsumption{}, "", "", err
		}
		return consumption, GrantSignatureEd25519, signature, nil
	}
	return store.consumeGrant(
		ctx, identity.TenantID, identity.WorkspaceID, approvalID,
		grantID, grantHash, nonce, sealConsumption, now,
	)
}

func recoverGrantConsumption(ctx context.Context, store ceremonyStore, consumer ConsumerIdentityProvider, now time.Time, approvalID, grantID, grantHash, nonce string) (Record, error) {
	identity, err := verifiedConsumerIdentity(ctx, consumer)
	if err != nil {
		return Record{}, err
	}
	record, err := store.get(ctx, identity.TenantID, identity.WorkspaceID, approvalID)
	if err != nil {
		return Record{}, err
	}
	if record.State != StateConsumed || record.Grant == nil || record.GrantConsumption == nil ||
		record.Grant.GrantID != grantID || record.Grant.GrantHash != grantHash || record.Grant.Nonce != nonce {
		return Record{}, ErrTransitionConflict
	}
	if record.ConsumedBy != identity.Subject || record.Grant.Audience != identity.Audience ||
		record.GrantConsumption.ConsumedBy != identity.Subject || record.GrantConsumption.Audience != identity.Audience {
		return Record{}, fmt.Errorf("%w: persisted consumption workload scope mismatch", ErrConsumerUnavailable)
	}
	if err := record.Grant.ValidateAt(now); err != nil {
		return Record{}, fmt.Errorf("%w: signed grant is inactive: %v", ErrTransitionConflict, err)
	}
	return record, nil
}

func verifiedConsumerIdentity(ctx context.Context, provider ConsumerIdentityProvider) (ConsumerIdentity, error) {
	if provider == nil {
		return ConsumerIdentity{}, fmt.Errorf("%w: verifier is not configured", ErrConsumerUnavailable)
	}
	identity, err := provider.LoadConsumerIdentity(ctx)
	if err != nil || !validToken(identity.Subject) || !validToken(identity.TenantID) ||
		!validToken(identity.WorkspaceID) || !validToken(identity.Audience) {
		return ConsumerIdentity{}, fmt.Errorf("%w: verified workload subject, tenant, workspace, and audience are required", ErrConsumerUnavailable)
	}
	return identity, nil
}
