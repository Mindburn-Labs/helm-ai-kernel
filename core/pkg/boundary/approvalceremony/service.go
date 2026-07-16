package approvalceremony

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

var (
	ErrHoldPending          = errors.New("approval ceremony hold pending")
	ErrBindingUnavailable   = errors.New("approval ceremony binding unavailable")
	ErrAuthorityUnavailable = errors.New("approval ceremony authority unavailable")
	ErrControlUnavailable   = errors.New("approval ceremony control identity unavailable")
	ErrConsumerUnavailable  = errors.New("approval ceremony consumer identity unavailable")
)

// BindingProvider resolves an immutable policy-owned effect binding. Routes
// pass only its opaque reference; they cannot construct the challenge body.
type BindingProvider interface {
	LoadApprovalBinding(context.Context, string, string, string) (ChallengeSpec, error)
}

type AuthorityProvider interface {
	LoadApprovalAuthority(context.Context, string, string, string, string, string) (approvalverify.TrustStore, error)
}

// ControlIdentityProvider extracts the authenticated control-plane subject and
// scope. Control routes never accept tenant or workspace as authority input.
type ControlIdentityProvider interface {
	LoadControlIdentity(context.Context) (ControlIdentity, error)
}

type ControlIdentity struct {
	Subject     string
	TenantID    string
	WorkspaceID string
}

// ConsumerIdentityProvider extracts a verified workload identity from the
// authenticated server context. Clients never submit consumed_by.
type ConsumerIdentityProvider interface {
	LoadConsumerIdentity(context.Context) (ConsumerIdentity, error)
}

type ConsumerIdentity struct {
	Subject     string
	TenantID    string
	WorkspaceID string
	Audience    string
}

type ServiceConfig struct {
	MinHoldDuration      time.Duration
	ChallengeTTL         time.Duration
	MaxChallengeLifetime time.Duration
	GrantTTL             time.Duration
	MaxAssertions        int
	ServerIdentity       string
	KernelTrustRootID    string
	SigningKeyRef        string
}

type ceremonyStore interface {
	createHold(context.Context, Record) (Record, error)
	Get(context.Context, string, string, string) (Record, error)
	issueChallenge(context.Context, string, string, string, contracts.ApprovalChallenge, time.Time) (Record, error)
	recordQuorum(context.Context, string, string, string, approvalverify.VerifiedApprovalRef, time.Time) (Record, error)
	issueGrant(context.Context, string, string, string, contracts.ApprovalGrant, string, string, time.Time) (Record, error)
	consumeGrant(context.Context, string, string, string, string, string, string, string, string, time.Time) (Record, error)
	deny(context.Context, string, string, string, time.Time) (Record, error)
	expire(context.Context, string, string, string, time.Time) (Record, error)
}

// Service is the only authority-bearing API. It creates IDs/nonces and
// timestamps, loads the tenant authority snapshot, verifies quorum, signs the
// exact grant, and delegates only atomic transitions to the store.
type Service struct {
	store     ceremonyStore
	bindings  BindingProvider
	authority AuthorityProvider
	control   ControlIdentityProvider
	consumer  ConsumerIdentityProvider
	signer    crypto.Signer
	clock     func() time.Time
	random    io.Reader
	config    ServiceConfig
}

func NewService(store *PostgresStore, bindings BindingProvider, authority AuthorityProvider, control ControlIdentityProvider, consumer ConsumerIdentityProvider, signer crypto.Signer, config ServiceConfig) (*Service, error) {
	return newService(store, bindings, authority, control, consumer, signer, time.Now, rand.Reader, config)
}

func newService(store ceremonyStore, bindings BindingProvider, authority AuthorityProvider, control ControlIdentityProvider, consumer ConsumerIdentityProvider, signer crypto.Signer, clock func() time.Time, random io.Reader, config ServiceConfig) (*Service, error) {
	if store == nil || bindings == nil || authority == nil || control == nil || consumer == nil || signer == nil || clock == nil || random == nil {
		return nil, errors.New("approval ceremony service dependencies are required")
	}
	if config.MinHoldDuration <= 0 || config.ChallengeTTL <= 0 || config.MaxChallengeLifetime <= 0 ||
		config.GrantTTL <= 0 || config.MaxAssertions <= 0 {
		return nil, errors.New("approval ceremony durations and max assertions must be positive")
	}
	if config.MaxChallengeLifetime <= config.MinHoldDuration ||
		config.ChallengeTTL > config.MaxChallengeLifetime-config.MinHoldDuration {
		return nil, errors.New("approval ceremony challenge ttl exceeds the post-hold lifetime budget")
	}
	if !validToken(config.ServerIdentity) || !validToken(config.KernelTrustRootID) || !validToken(config.SigningKeyRef) {
		return nil, errors.New("approval ceremony server and signing identities are required")
	}
	return &Service{
		store: store, bindings: bindings, authority: authority, control: control, consumer: consumer, signer: signer,
		clock: clock, random: random, config: config,
	}, nil
}

func (s *Service) BeginHold(ctx context.Context, bindingRef string) (Record, error) {
	if !validToken(bindingRef) {
		return Record{}, invalidRecord("binding_ref is required")
	}
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	spec, err := s.bindings.LoadApprovalBinding(
		ctx, identity.TenantID, identity.WorkspaceID, bindingRef,
	)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrBindingUnavailable, err)
	}
	if err := spec.Validate(); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrBindingUnavailable, err)
	}
	if spec.TenantID != identity.TenantID || spec.WorkspaceID != identity.WorkspaceID || spec.BindingRef != bindingRef {
		return Record{}, fmt.Errorf("%w: binding scope or reference mismatch", ErrBindingUnavailable)
	}
	if spec.ServerIdentity != s.config.ServerIdentity || spec.Quorum > s.config.MaxAssertions {
		return Record{}, invalidRecord("challenge_spec exceeds configured authority")
	}
	if _, err := s.loadAuthority(ctx, spec); err != nil {
		return Record{}, err
	}
	approvalID, err := s.randomToken("approval", 16)
	if err != nil {
		return Record{}, err
	}
	now := s.now()
	return s.store.createHold(ctx, Record{
		ApprovalID: approvalID, TenantID: spec.TenantID, WorkspaceID: spec.WorkspaceID,
		State: StateHoldPending, HoldStartedAt: now, Spec: spec,
		CreatedAt: now, UpdatedAt: now, Version: 1,
	})
}

func (s *Service) IssueChallenge(ctx context.Context, approvalID string) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	record, err := s.store.Get(ctx, identity.TenantID, identity.WorkspaceID, approvalID)
	if err != nil {
		return Record{}, err
	}
	if record.State != StateHoldPending {
		return Record{}, ErrTransitionConflict
	}
	now := s.now()
	eligibleAt := record.HoldStartedAt.Add(s.config.MinHoldDuration)
	if now.Before(eligibleAt) {
		return Record{}, ErrHoldPending
	}
	maxExpiresAt := record.HoldStartedAt.Add(s.config.MaxChallengeLifetime)
	if !maxExpiresAt.After(now) {
		return Record{}, ErrTransitionConflict
	}
	expiresAt := now.Add(s.config.ChallengeTTL)
	if expiresAt.After(maxExpiresAt) {
		expiresAt = maxExpiresAt
	}
	if _, err := s.loadAuthority(ctx, record.Spec); err != nil {
		return Record{}, err
	}
	challengeID, err := s.randomToken("challenge", 16)
	if err != nil {
		return Record{}, err
	}
	nonce, err := s.randomHex(32)
	if err != nil {
		return Record{}, err
	}
	spec := record.Spec
	challenge, err := (contracts.ApprovalChallenge{
		Domain: contracts.ApprovalChallengeDomainV1, SchemaVersion: contracts.ApprovalChallengeSchemaV1,
		ContractVersion: contracts.ApprovalChallengeContractV1,
		ChallengeID:     challengeID, ApprovalID: record.ApprovalID, TenantID: spec.TenantID,
		WorkspaceID: spec.WorkspaceID, Audience: spec.Audience, PackID: spec.PackID,
		PackVersion: spec.PackVersion, PackManifestHash: spec.PackManifestHash, Action: spec.Action,
		IntentHash: spec.IntentHash, EffectHash: spec.EffectHash, PlanHash: spec.PlanHash,
		Decision: spec.Decision, PolicyVersion: spec.PolicyVersion, PolicyEpoch: spec.PolicyEpoch,
		PolicyHash: spec.PolicyHash, AuthoritySource: spec.AuthoritySource,
		AuthorityVersion: spec.AuthorityVersion, AuthoritySnapshotHash: spec.AuthoritySnapshotHash,
		RequiredRole: spec.RequiredRole, Quorum: spec.Quorum, ServerIdentity: spec.ServerIdentity,
		HoldStartedAt: record.HoldStartedAt, EligibleAt: eligibleAt, IssuedAt: now,
		ExpiresAt: expiresAt, Nonce: nonce,
	}).Seal()
	if err != nil {
		return Record{}, fmt.Errorf("seal approval challenge: %w", err)
	}
	return s.store.issueChallenge(ctx, identity.TenantID, identity.WorkspaceID, approvalID, challenge, now)
}

func (s *Service) VerifyQuorum(ctx context.Context, approvalID string, assertions []contracts.ApprovalAssertion) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	record, err := s.store.Get(ctx, identity.TenantID, identity.WorkspaceID, approvalID)
	if err != nil {
		return Record{}, err
	}
	if record.State != StateChallengeIssued || record.Challenge == nil {
		return Record{}, ErrTransitionConflict
	}
	trustStore, err := s.loadAuthority(ctx, record.Spec)
	if err != nil {
		return Record{}, err
	}
	now := s.now()
	verified, err := approvalverify.VerifyQuorum(
		*record.Challenge, assertions, trustStore,
		approvalverify.VerifyOptions{
			Expected: expectedBinding(record.Spec, *record.Challenge), MinHoldDuration: s.config.MinHoldDuration,
			MaxChallengeTTL: s.config.MaxChallengeLifetime, MaxAssertions: s.config.MaxAssertions,
		},
		now,
	)
	if err != nil {
		return Record{}, err
	}
	return s.store.recordQuorum(ctx, identity.TenantID, identity.WorkspaceID, approvalID, verified, now)
}

func (s *Service) IssueGrant(ctx context.Context, approvalID string) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	record, err := s.store.Get(ctx, identity.TenantID, identity.WorkspaceID, approvalID)
	if err != nil {
		return Record{}, err
	}
	if record.State != StateQuorumVerified || record.VerifiedRef == nil || record.Challenge == nil {
		return Record{}, ErrTransitionConflict
	}
	now := s.now()
	if now.Before(record.VerifiedRef.VerifiedAt) {
		return Record{}, ErrTransitionConflict
	}
	expiresAt := now.Add(s.config.GrantTTL)
	if expiresAt.After(record.Challenge.ExpiresAt) {
		expiresAt = record.Challenge.ExpiresAt
	}
	if !expiresAt.After(now) {
		return Record{}, ErrTransitionConflict
	}
	grantID, err := s.randomToken("grant", 16)
	if err != nil {
		return Record{}, err
	}
	nonce, err := s.randomHex(32)
	if err != nil {
		return Record{}, err
	}
	ceremonyHash, err := CeremonyCommitment(record)
	if err != nil {
		return Record{}, err
	}
	verified := record.VerifiedRef
	grant, err := (contracts.ApprovalGrant{
		SchemaVersion: contracts.ApprovalGrantSchemaV1, ContractVersion: contracts.ApprovalGrantContractV1,
		GrantID: grantID, TenantID: verified.TenantID, WorkspaceID: verified.WorkspaceID,
		Audience: verified.Audience, PackID: verified.PackID, PackVersion: verified.PackVersion,
		PackManifestHash: verified.PackManifestHash, Action: verified.Action,
		IntentHash: verified.IntentHash, EffectHash: verified.EffectHash, PlanHash: verified.PlanHash,
		Decision: verified.Decision, PolicyVersion: verified.PolicyVersion,
		PolicyEpoch: verified.PolicyEpoch, PolicyHash: verified.PolicyHash,
		ApprovalID: verified.ApprovalID, CeremonyHash: ceremonyHash, SignerSetHash: verified.SignerSetHash,
		ServerIdentity: verified.ServerIdentity, KernelTrustRootID: s.config.KernelTrustRootID,
		SigningKeyRef: s.config.SigningKeyRef, IssuedAt: now, ExpiresAt: expiresAt, Nonce: nonce,
	}).Seal()
	if err != nil {
		return Record{}, fmt.Errorf("seal approval grant: %w", err)
	}
	signature, err := SignApprovalGrant(grant, s.signer)
	if err != nil {
		return Record{}, err
	}
	return s.store.issueGrant(
		ctx, identity.TenantID, identity.WorkspaceID, approvalID,
		grant, GrantSignatureEd25519, signature, now,
	)
}

func (s *Service) ConsumeGrant(ctx context.Context, approvalID, grantID, grantHash, nonce string) (Record, error) {
	identity, err := s.consumer.LoadConsumerIdentity(ctx)
	if err != nil || !validToken(identity.Subject) || !validToken(identity.TenantID) ||
		!validToken(identity.WorkspaceID) || !validToken(identity.Audience) {
		return Record{}, fmt.Errorf("%w: verified workload subject, tenant, workspace, and audience are required", ErrConsumerUnavailable)
	}
	return s.store.consumeGrant(
		ctx, identity.TenantID, identity.WorkspaceID, approvalID,
		grantID, grantHash, nonce, identity.Subject, identity.Audience, s.now(),
	)
}

func (s *Service) Deny(ctx context.Context, approvalID string) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	return s.store.deny(ctx, identity.TenantID, identity.WorkspaceID, approvalID, s.now())
}

func (s *Service) Expire(ctx context.Context, approvalID string) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	return s.store.expire(ctx, identity.TenantID, identity.WorkspaceID, approvalID, s.now())
}

func (s *Service) Get(ctx context.Context, approvalID string) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	return s.store.Get(ctx, identity.TenantID, identity.WorkspaceID, approvalID)
}

func (s *Service) controlIdentity(ctx context.Context) (ControlIdentity, error) {
	identity, err := s.control.LoadControlIdentity(ctx)
	if err != nil || !validToken(identity.Subject) || !validToken(identity.TenantID) || !validToken(identity.WorkspaceID) {
		return ControlIdentity{}, fmt.Errorf("%w: verified control subject, tenant, and workspace are required", ErrControlUnavailable)
	}
	return identity, nil
}

func (s *Service) loadAuthority(ctx context.Context, spec ChallengeSpec) (approvalverify.TrustStore, error) {
	store, err := s.authority.LoadApprovalAuthority(
		ctx, spec.TenantID, spec.WorkspaceID, spec.AuthoritySource,
		spec.AuthorityVersion, spec.AuthoritySnapshotHash,
	)
	if err != nil {
		return approvalverify.TrustStore{}, fmt.Errorf("%w: %v", ErrAuthorityUnavailable, err)
	}
	if store.AuthoritySource != spec.AuthoritySource || store.AuthorityVersion != spec.AuthorityVersion ||
		store.AuthoritySnapshotHash != spec.AuthoritySnapshotHash {
		return approvalverify.TrustStore{}, fmt.Errorf("%w: snapshot metadata mismatch", ErrAuthorityUnavailable)
	}
	return store, nil
}

func (s *Service) now() time.Time {
	return s.clock().UTC().Truncate(time.Microsecond)
}

func (s *Service) randomToken(prefix string, size int) (string, error) {
	raw, err := s.randomBytes(size)
	if err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(raw), nil
}

func (s *Service) randomHex(size int) (string, error) {
	raw, err := s.randomBytes(size)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func (s *Service) randomBytes(size int) ([]byte, error) {
	raw := make([]byte, size)
	if _, err := io.ReadFull(s.random, raw); err != nil {
		return nil, fmt.Errorf("generate approval ceremony randomness: %w", err)
	}
	return raw, nil
}

func expectedBinding(spec ChallengeSpec, challenge contracts.ApprovalChallenge) approvalverify.ExpectedBinding {
	return approvalverify.ExpectedBinding{
		ChallengeID: challenge.ChallengeID, ChallengeHash: challenge.ChallengeHash,
		ApprovalID: challenge.ApprovalID, TenantID: spec.TenantID,
		WorkspaceID: spec.WorkspaceID, Audience: spec.Audience,
		PackID: spec.PackID, PackVersion: spec.PackVersion,
		PackManifestHash: spec.PackManifestHash, Action: spec.Action,
		IntentHash: spec.IntentHash, EffectHash: spec.EffectHash,
		PlanHash: spec.PlanHash, Decision: spec.Decision,
		PolicyVersion: spec.PolicyVersion, PolicyEpoch: spec.PolicyEpoch,
		PolicyHash: spec.PolicyHash, AuthoritySource: spec.AuthoritySource,
		AuthorityVersion: spec.AuthorityVersion, AuthoritySnapshotHash: spec.AuthoritySnapshotHash,
		RequiredRole: spec.RequiredRole, Quorum: spec.Quorum,
		ServerIdentity: spec.ServerIdentity,
	}
}

func CeremonyCommitment(record Record) (string, error) {
	payload, err := ceremonyCommitmentPayload(record)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(hash[:]), nil
}

func ceremonyCommitmentPayload(record Record) ([]byte, error) {
	if record.Challenge == nil || record.VerifiedRef == nil {
		return nil, invalidRecord("ceremony commitment requires challenge and verified_ref")
	}
	specHash, err := canonicalize.CanonicalHash(record.Spec)
	if err != nil {
		return nil, fmt.Errorf("commit approval challenge spec: %w", err)
	}
	payload, err := canonicalize.JCS(struct {
		Domain            string    `json:"domain"`
		ApprovalID        string    `json:"approval_id"`
		TenantID          string    `json:"tenant_id"`
		WorkspaceID       string    `json:"workspace_id"`
		ChallengeSpecHash string    `json:"challenge_spec_hash"`
		ChallengeHash     string    `json:"challenge_hash"`
		SignerSetHash     string    `json:"signer_set_hash"`
		VerifiedAt        time.Time `json:"verified_at"`
	}{
		Domain: "HELM/ApprovalCeremonyCommitment/v1", ApprovalID: record.ApprovalID,
		TenantID: record.TenantID, WorkspaceID: record.WorkspaceID,
		ChallengeSpecHash: "sha256:" + specHash, ChallengeHash: record.Challenge.ChallengeHash,
		SignerSetHash: record.VerifiedRef.SignerSetHash,
		VerifiedAt:    record.VerifiedRef.VerifiedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("commit approval ceremony: %w", err)
	}
	return payload, nil
}
