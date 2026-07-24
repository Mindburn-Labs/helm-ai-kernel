// quantum_posture: this ceremony uses the GeneratedSpec approval contract's
// classical Ed25519 signatures only. It makes no hybrid or post-quantum claim.
// Package generatedspecapprovalceremony owns the source-side lifecycle for a
// GeneratedSpec approval. Store is deliberately an interface: production must
// provide durable, atomic transitions; the package's memory store is test-only.
package generatedspecapprovalceremony

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapproval"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type State string

const (
	StateHoldPending     State = "HOLD_PENDING"
	StateChallengeIssued State = "CHALLENGE_ISSUED"
	StateQuorumVerified  State = "QUORUM_VERIFIED"
	StateGrantIssued     State = "GRANT_ISSUED"
	StateConsumed        State = "CONSUMED"
	StateDenied          State = "DENIED"
	StateExpired         State = "EXPIRED"
)

var (
	ErrInvalidRecord        = errors.New("generated spec approval ceremony record invalid")
	ErrNotFound             = errors.New("generated spec approval ceremony not found")
	ErrTransitionConflict   = errors.New("generated spec approval ceremony transition conflict")
	ErrHoldPending          = errors.New("generated spec approval ceremony hold pending")
	ErrExpired              = errors.New("generated spec approval ceremony expired")
	ErrBindingUnavailable   = errors.New("generated spec approval ceremony binding unavailable")
	ErrAuthorityUnavailable = errors.New("generated spec approval ceremony authority unavailable")
	ErrControlUnavailable   = errors.New("generated spec approval ceremony control identity unavailable")
	ErrConsumerUnavailable  = errors.New("generated spec approval ceremony consumer identity unavailable")
)

// Binding is the server-owned, immutable input to a challenge. Clients submit
// only BindingRef to the provider; they never construct this value.
type Binding struct {
	BindingRef            string
	TenantID              string
	WorkspaceID           string
	Audience              string
	GeneratedSpecID       string
	GeneratedSpecHash     string
	ExecutionPlanHash     string
	PlanTransactionHash   string
	WriteSetHash          string
	VerificationScopeHash string
	PolicyEnvelopeHash    string
	PolicyVersion         string
	PolicyEpoch           string
	Action                string
	RequestingPrincipalID string
	AuthoritySource       string
	AuthorityVersion      string
	AuthoritySnapshotHash string
	RequiredRole          string
	Quorum                int
	ServerIdentity        string
}

func (b Binding) Validate() error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{"binding_ref", b.BindingRef}, {"tenant_id", b.TenantID}, {"workspace_id", b.WorkspaceID},
		{"generated_spec_id", b.GeneratedSpecID}, {"policy_version", b.PolicyVersion},
		{"policy_epoch", b.PolicyEpoch}, {"requesting_principal_id", b.RequestingPrincipalID},
		{"authority_source", b.AuthoritySource}, {"authority_version", b.AuthorityVersion},
		{"required_role", b.RequiredRole}, {"server_identity", b.ServerIdentity},
	} {
		if !validToken(field.value) {
			return invalidRecord("binding " + field.name + " is invalid")
		}
	}
	if b.Audience != contracts.GeneratedSpecApprovalAudienceV1 || b.Action != contracts.GeneratedSpecApprovalActionV1 {
		return invalidRecord("binding audience or action is unsupported")
	}
	for _, field := range []struct {
		name  string
		value string
	}{
		{"generated_spec_hash", b.GeneratedSpecHash}, {"execution_plan_hash", b.ExecutionPlanHash},
		{"plan_transaction_hash", b.PlanTransactionHash}, {"write_set_hash", b.WriteSetHash},
		{"verification_scope_hash", b.VerificationScopeHash}, {"policy_envelope_hash", b.PolicyEnvelopeHash},
		{"authority_snapshot_hash", b.AuthoritySnapshotHash},
	} {
		if !validSHA256(field.value) {
			return invalidRecord("binding " + field.name + " is invalid")
		}
	}
	if b.Quorum <= 0 {
		return invalidRecord("binding quorum must be positive")
	}
	return nil
}

// BindingProvider resolves a server-side opaque binding. The control plane
// supplies scope only through its verified identity, never in request fields.
type BindingProvider interface {
	LoadGeneratedSpecApprovalBinding(context.Context, string, string, string) (Binding, error)
}

// AuthorityProvider loads the exact trust snapshot named by the binding.
// It is the authority owner; control-plane callers cannot replace its result.
type AuthorityProvider interface {
	LoadGeneratedSpecApprovalAuthority(context.Context, string, string, string, string, string) (approvalverify.TrustStore, error)
}

type ControlIdentity struct {
	Subject     string
	TenantID    string
	WorkspaceID string
}

type ControlIdentityProvider interface {
	LoadControlIdentity(context.Context) (ControlIdentity, error)
}

type ConsumerIdentity struct {
	Subject     string
	TenantID    string
	WorkspaceID string
	Audience    string
}

type ConsumerIdentityProvider interface {
	LoadConsumerIdentity(context.Context) (ConsumerIdentity, error)
}

// GrantSignatureVerifier pins the Kernel signing key and trust-root metadata.
// It is required at the persistence boundary: envelope syntax alone is never
// proof that a stored grant or consumption record is authentic.
type GrantSignatureVerifier interface {
	VerifyGrant(generatedspecapproval.SignedGrant, time.Time) error
	VerifyConsumption(generatedspecapproval.SignedConsumption, generatedspecapproval.SignedGrant) error
}

// Record contains source-owned lifecycle state. Raw assertions are retained so
// IssueGrant can verify them again against a freshly loaded exact snapshot.
// A generatedspecapproval.VerifiedApprovalRef is intentionally never stored.
type Record struct {
	ApprovalID  string
	TenantID    string
	WorkspaceID string
	State       State

	Binding           Binding
	HoldStartedAt     time.Time
	Challenge         *contracts.GeneratedSpecApprovalChallenge
	Assertions        []contracts.GeneratedSpecApprovalAssertion
	QuorumVerifiedAt  *time.Time
	SignedGrant       *generatedspecapproval.SignedGrant
	SignedConsumption *generatedspecapproval.SignedConsumption
	ExpiresAt         *time.Time
	ConsumedAt        *time.Time
	ConsumedBy        string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Version           int64
}

// ConsumptionSealer must run inside Store.ConsumeGrant's atomic transition.
// A durable implementation must keep the grant state update and resulting
// signed consumption in the same transaction.
type ConsumptionSealer func(generatedspecapproval.SignedGrant, string, time.Time) (generatedspecapproval.SignedConsumption, error)

// Store is the future production persistence seam. Each transition must be
// atomic and scope by tenant/workspace/approval ID. IssueGrant and ConsumeGrant
// must validate through the pinned GrantSignatureVerifier inside the transition.
// The package's unexported memory implementation exists only for unit tests.
type Store interface {
	CreateHold(context.Context, Record) (Record, error)
	Get(context.Context, string, string, string) (Record, error)
	IssueChallenge(context.Context, string, string, string, contracts.GeneratedSpecApprovalChallenge, time.Time) (Record, error)
	RecordQuorum(context.Context, string, string, string, []contracts.GeneratedSpecApprovalAssertion, time.Time) (Record, error)
	IssueGrant(context.Context, string, string, string, generatedspecapproval.SignedGrant, GrantSignatureVerifier, time.Time) (Record, error)
	ConsumeGrant(context.Context, string, string, string, string, string, string, string, string, GrantSignatureVerifier, time.Time, ConsumptionSealer) (Record, error)
	Deny(context.Context, string, string, string, time.Time) (Record, error)
	Expire(context.Context, string, string, string, time.Time) (Record, error)
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

// Service is the only authority-bearing API in this package. It sources the
// binding, authority snapshot, and identities server-side before transitions.
type Service struct {
	store     Store
	bindings  BindingProvider
	authority AuthorityProvider
	control   ControlIdentityProvider
	consumer  ConsumerIdentityProvider
	signer    crypto.Signer
	verifier  GrantSignatureVerifier
	clock     func() time.Time
	random    io.Reader
	config    ServiceConfig
}

func NewService(store Store, bindings BindingProvider, authority AuthorityProvider, control ControlIdentityProvider, consumer ConsumerIdentityProvider, signer crypto.Signer, verifier GrantSignatureVerifier, config ServiceConfig) (*Service, error) {
	return newService(store, bindings, authority, control, consumer, signer, verifier, time.Now, rand.Reader, config)
}

func newService(store Store, bindings BindingProvider, authority AuthorityProvider, control ControlIdentityProvider, consumer ConsumerIdentityProvider, signer crypto.Signer, verifier GrantSignatureVerifier, clock func() time.Time, random io.Reader, config ServiceConfig) (*Service, error) {
	if store == nil || bindings == nil || authority == nil || control == nil || consumer == nil || signer == nil || verifier == nil || clock == nil || random == nil {
		return nil, errors.New("generated spec approval ceremony dependencies are required")
	}
	if config.MinHoldDuration <= 0 || config.ChallengeTTL <= 0 || config.MaxChallengeLifetime <= config.MinHoldDuration || config.GrantTTL <= 0 || config.MaxAssertions <= 0 {
		return nil, errors.New("generated spec approval ceremony durations and max assertions are invalid")
	}
	if config.ChallengeTTL > config.MaxChallengeLifetime-config.MinHoldDuration || !validToken(config.ServerIdentity) || !validToken(config.KernelTrustRootID) || !validToken(config.SigningKeyRef) {
		return nil, errors.New("generated spec approval ceremony authority configuration is invalid")
	}
	return &Service{store: store, bindings: bindings, authority: authority, control: control, consumer: consumer, signer: signer, verifier: verifier, clock: clock, random: random, config: config}, nil
}

func (s *Service) BeginHold(ctx context.Context, bindingRef string) (Record, error) {
	if !validToken(bindingRef) {
		return Record{}, invalidRecord("binding_ref is required")
	}
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	binding, err := s.bindings.LoadGeneratedSpecApprovalBinding(ctx, identity.TenantID, identity.WorkspaceID, bindingRef)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrBindingUnavailable, err)
	}
	if err := binding.Validate(); err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrBindingUnavailable, err)
	}
	if binding.BindingRef != bindingRef || binding.TenantID != identity.TenantID || binding.WorkspaceID != identity.WorkspaceID || binding.ServerIdentity != s.config.ServerIdentity || binding.Quorum > s.config.MaxAssertions {
		return Record{}, fmt.Errorf("%w: binding scope or configured authority mismatch", ErrBindingUnavailable)
	}
	if _, err := s.loadAuthority(ctx, binding); err != nil {
		return Record{}, err
	}
	approvalID, err := s.randomToken("approval", 16)
	if err != nil {
		return Record{}, err
	}
	now := s.now()
	return s.store.CreateHold(ctx, Record{
		ApprovalID: approvalID, TenantID: identity.TenantID, WorkspaceID: identity.WorkspaceID,
		State: StateHoldPending, Binding: binding, HoldStartedAt: now, CreatedAt: now, UpdatedAt: now, Version: 1,
	})
}

func (s *Service) IssueChallenge(ctx context.Context, approvalID string) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	record, err := s.get(ctx, identity.TenantID, identity.WorkspaceID, approvalID)
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
		return Record{}, ErrExpired
	}
	if _, err := s.loadAuthority(ctx, record.Binding); err != nil {
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
	expiresAt := now.Add(s.config.ChallengeTTL)
	if expiresAt.After(maxExpiresAt) {
		expiresAt = maxExpiresAt
	}
	challenge, err := challengeFor(record, challengeID, nonce, eligibleAt, now, expiresAt)
	if err != nil {
		return Record{}, err
	}
	return s.store.IssueChallenge(ctx, identity.TenantID, identity.WorkspaceID, approvalID, challenge, now)
}

func (s *Service) VerifyQuorum(ctx context.Context, approvalID string, assertions []contracts.GeneratedSpecApprovalAssertion) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	record, err := s.get(ctx, identity.TenantID, identity.WorkspaceID, approvalID)
	if err != nil {
		return Record{}, err
	}
	if record.State != StateChallengeIssued || record.Challenge == nil {
		return Record{}, ErrTransitionConflict
	}
	now := s.now()
	if err := s.ensureChallengeActive(record, now); err != nil {
		return Record{}, err
	}
	if _, err := s.verify(ctx, record, assertions, now); err != nil {
		return Record{}, err
	}
	return s.store.RecordQuorum(ctx, identity.TenantID, identity.WorkspaceID, approvalID, assertions, now)
}

// IssueGrant intentionally reconstructs verification from raw stored
// assertions. A VerifiedApprovalRef is an in-memory verifier capability, not
// durable issuance authority and is never decoded from Record.
func (s *Service) IssueGrant(ctx context.Context, approvalID string) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	record, err := s.get(ctx, identity.TenantID, identity.WorkspaceID, approvalID)
	if err != nil {
		return Record{}, err
	}
	if record.State != StateQuorumVerified || record.Challenge == nil || record.QuorumVerifiedAt == nil {
		return Record{}, ErrTransitionConflict
	}
	now := s.now()
	if err := s.ensureChallengeActive(record, now); err != nil {
		return Record{}, err
	}
	verified, err := s.verify(ctx, record, record.Assertions, now)
	if err != nil {
		return Record{}, err
	}
	grantID, err := s.randomToken("grant", 16)
	if err != nil {
		return Record{}, err
	}
	nonce, err := s.randomHex(32)
	if err != nil {
		return Record{}, err
	}
	signed, err := generatedspecapproval.IssueGrant(*record.Challenge, verified, grantID, nonce, s.signer, generatedspecapproval.IssuerConfig{
		GrantTTL: s.config.GrantTTL, ServerIdentity: s.config.ServerIdentity, KernelTrustRootID: s.config.KernelTrustRootID, SigningKeyRef: s.config.SigningKeyRef,
	}, now)
	if err != nil {
		return Record{}, err
	}
	if err := s.verifier.VerifyGrant(signed, now); err != nil {
		return Record{}, err
	}
	return s.store.IssueGrant(ctx, identity.TenantID, identity.WorkspaceID, approvalID, signed, s.verifier, now)
}

func (s *Service) ConsumeGrant(ctx context.Context, approvalID, grantID, grantHash, nonce string) (Record, error) {
	identity, err := s.consumerIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	now := s.now()
	return s.store.ConsumeGrant(ctx, identity.TenantID, identity.WorkspaceID, approvalID, grantID, grantHash, nonce, identity.Subject, identity.Audience, s.verifier, now,
		func(signed generatedspecapproval.SignedGrant, consumedBy string, consumedAt time.Time) (generatedspecapproval.SignedConsumption, error) {
			if signed.Grant.Audience != identity.Audience {
				return generatedspecapproval.SignedConsumption{}, fmt.Errorf("%w: signed grant workload scope mismatch", ErrConsumerUnavailable)
			}
			consumption, err := generatedspecapproval.NewConsumption(signed.Grant, consumedBy, consumedAt)
			if err != nil {
				return generatedspecapproval.SignedConsumption{}, err
			}
			return generatedspecapproval.SignConsumption(consumption, s.signer)
		},
	)
}

// RecoverGrantConsumption returns the same persisted consumption only to the
// same verified workload. It never performs a second consume transition.
func (s *Service) RecoverGrantConsumption(ctx context.Context, approvalID, grantID, grantHash, nonce string) (Record, error) {
	identity, err := s.consumerIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	record, err := s.get(ctx, identity.TenantID, identity.WorkspaceID, approvalID)
	if err != nil {
		return Record{}, err
	}
	if record.State != StateConsumed || record.SignedGrant == nil || record.SignedConsumption == nil || record.ConsumedAt == nil ||
		record.SignedGrant.Grant.GrantID != grantID || record.SignedGrant.Grant.GrantHash != grantHash || record.SignedGrant.Grant.Nonce != nonce {
		return Record{}, ErrTransitionConflict
	}
	if record.ConsumedBy != identity.Subject || record.SignedConsumption.Consumption.ConsumedBy != identity.Subject || record.SignedGrant.Grant.Audience != identity.Audience {
		return Record{}, fmt.Errorf("%w: persisted consumption identity mismatch", ErrConsumerUnavailable)
	}
	now := s.now()
	if err := ensureGrantActive(record.SignedGrant.Grant, now); err != nil {
		return Record{}, err
	}
	if err := s.verifier.VerifyGrant(*record.SignedGrant, now); err != nil {
		return Record{}, err
	}
	if err := s.verifier.VerifyConsumption(*record.SignedConsumption, *record.SignedGrant); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *Service) Deny(ctx context.Context, approvalID string) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	return s.store.Deny(ctx, identity.TenantID, identity.WorkspaceID, approvalID, s.now())
}

func (s *Service) Expire(ctx context.Context, approvalID string) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	return s.store.Expire(ctx, identity.TenantID, identity.WorkspaceID, approvalID, s.now())
}

func (s *Service) Get(ctx context.Context, approvalID string) (Record, error) {
	identity, err := s.controlIdentity(ctx)
	if err != nil {
		return Record{}, err
	}
	return s.get(ctx, identity.TenantID, identity.WorkspaceID, approvalID)
}

func (s *Service) verify(ctx context.Context, record Record, assertions []contracts.GeneratedSpecApprovalAssertion, now time.Time) (generatedspecapproval.VerifiedApprovalRef, error) {
	if record.Challenge == nil {
		return generatedspecapproval.VerifiedApprovalRef{}, ErrTransitionConflict
	}
	// A persisted challenge must still honor the configured per-issuance TTL.
	// IssueChallenge sets ExpiresAt = IssuedAt + ChallengeTTL (clamped only to
	// MaxChallengeLifetime), so a larger span means the stored challenge was
	// resealed with an extended expiry. The verifier's MaxChallengeTTL option
	// spans the full hold-to-expiry lifetime, so it cannot catch that tampering
	// on its own.
	if record.Challenge.ExpiresAt.Sub(record.Challenge.IssuedAt) > s.config.ChallengeTTL {
		return generatedspecapproval.VerifiedApprovalRef{}, fmt.Errorf("%w: persisted challenge ttl exceeds configured challenge ttl", generatedspecapproval.ErrVerificationFailed)
	}
	trust, err := s.loadAuthority(ctx, record.Binding)
	if err != nil {
		return generatedspecapproval.VerifiedApprovalRef{}, err
	}
	return generatedspecapproval.VerifyGeneratedSpecQuorum(*record.Challenge, assertions, trust, generatedspecapproval.VerifyOptions{
		Expected: expectedBinding(record.Binding, *record.Challenge), MinHoldDuration: s.config.MinHoldDuration,
		MaxChallengeTTL: s.config.MaxChallengeLifetime, MaxAssertions: s.config.MaxAssertions,
	}, now)
}

func (s *Service) ensureChallengeActive(record Record, now time.Time) error {
	if record.Challenge == nil {
		return ErrTransitionConflict
	}
	if !now.Before(record.Challenge.ExpiresAt) {
		return fmt.Errorf("%w: challenge has expired", ErrExpired)
	}
	if err := record.Challenge.ValidateAt(now); err != nil {
		return fmt.Errorf("%w: challenge is not active: %v", ErrTransitionConflict, err)
	}
	return nil
}

func ensureGrantActive(grant contracts.GeneratedSpecApprovalGrant, now time.Time) error {
	if !now.Before(grant.ExpiresAt) {
		return fmt.Errorf("%w: grant has expired", ErrExpired)
	}
	if err := grant.ValidateAt(now); err != nil {
		return fmt.Errorf("%w: grant is not active: %v", ErrTransitionConflict, err)
	}
	return nil
}

func (s *Service) get(ctx context.Context, tenantID, workspaceID, approvalID string) (Record, error) {
	record, err := s.store.Get(ctx, tenantID, workspaceID, approvalID)
	if err != nil {
		return Record{}, err
	}
	if err := record.validate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *Service) loadAuthority(ctx context.Context, binding Binding) (approvalverify.TrustStore, error) {
	store, err := s.authority.LoadGeneratedSpecApprovalAuthority(ctx, binding.TenantID, binding.WorkspaceID, binding.AuthoritySource, binding.AuthorityVersion, binding.AuthoritySnapshotHash)
	if err != nil {
		return approvalverify.TrustStore{}, fmt.Errorf("%w: %v", ErrAuthorityUnavailable, err)
	}
	if store.AuthoritySource != binding.AuthoritySource || store.AuthorityVersion != binding.AuthorityVersion || store.AuthoritySnapshotHash != binding.AuthoritySnapshotHash {
		return approvalverify.TrustStore{}, fmt.Errorf("%w: snapshot metadata mismatch", ErrAuthorityUnavailable)
	}
	return store, nil
}

func (s *Service) controlIdentity(ctx context.Context) (ControlIdentity, error) {
	identity, err := s.control.LoadControlIdentity(ctx)
	if err != nil || !validToken(identity.Subject) || !validToken(identity.TenantID) || !validToken(identity.WorkspaceID) {
		return ControlIdentity{}, fmt.Errorf("%w: verified control subject, tenant, and workspace are required", ErrControlUnavailable)
	}
	return identity, nil
}

func (s *Service) consumerIdentity(ctx context.Context) (ConsumerIdentity, error) {
	identity, err := s.consumer.LoadConsumerIdentity(ctx)
	if err != nil || !validToken(identity.Subject) || !validToken(identity.TenantID) || !validToken(identity.WorkspaceID) || !validToken(identity.Audience) {
		return ConsumerIdentity{}, fmt.Errorf("%w: verified workload subject, tenant, workspace, and audience are required", ErrConsumerUnavailable)
	}
	return identity, nil
}

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

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
		return nil, fmt.Errorf("generated spec approval ceremony randomness: %w", err)
	}
	return raw, nil
}

func challengeFor(record Record, challengeID, nonce string, eligibleAt, issuedAt, expiresAt time.Time) (contracts.GeneratedSpecApprovalChallenge, error) {
	b := record.Binding
	challenge, err := (contracts.GeneratedSpecApprovalChallenge{
		Domain: contracts.GeneratedSpecApprovalChallengeDomainV1, SchemaVersion: contracts.GeneratedSpecApprovalChallengeSchemaV1,
		ContractVersion: contracts.GeneratedSpecApprovalChallengeContractV1,
		ChallengeID:     challengeID, ApprovalID: record.ApprovalID, TenantID: b.TenantID, WorkspaceID: b.WorkspaceID, Audience: b.Audience,
		GeneratedSpecID: b.GeneratedSpecID, GeneratedSpecHash: b.GeneratedSpecHash, ExecutionPlanHash: b.ExecutionPlanHash,
		PlanTransactionHash: b.PlanTransactionHash, WriteSetHash: b.WriteSetHash, VerificationScopeHash: b.VerificationScopeHash,
		PolicyEnvelopeHash: b.PolicyEnvelopeHash, PolicyVersion: b.PolicyVersion, PolicyEpoch: b.PolicyEpoch, Action: b.Action,
		RequestingPrincipalID: b.RequestingPrincipalID, AuthoritySource: b.AuthoritySource, AuthorityVersion: b.AuthorityVersion,
		AuthoritySnapshotHash: b.AuthoritySnapshotHash, RequiredRole: b.RequiredRole, Quorum: b.Quorum, ServerIdentity: b.ServerIdentity,
		HoldStartedAt: record.HoldStartedAt, EligibleAt: eligibleAt, IssuedAt: issuedAt, ExpiresAt: expiresAt, Nonce: nonce,
	}).Seal()
	if err != nil {
		return contracts.GeneratedSpecApprovalChallenge{}, fmt.Errorf("seal generated spec approval challenge: %w", err)
	}
	return challenge, nil
}

func expectedBinding(binding Binding, challenge contracts.GeneratedSpecApprovalChallenge) generatedspecapproval.ExpectedBinding {
	return generatedspecapproval.ExpectedBinding{
		ChallengeID: challenge.ChallengeID, ChallengeHash: challenge.ChallengeHash, ApprovalID: challenge.ApprovalID,
		TenantID: binding.TenantID, WorkspaceID: binding.WorkspaceID, Audience: binding.Audience,
		GeneratedSpecID: binding.GeneratedSpecID, GeneratedSpecHash: binding.GeneratedSpecHash,
		ExecutionPlanHash: binding.ExecutionPlanHash, PlanTransactionHash: binding.PlanTransactionHash,
		WriteSetHash: binding.WriteSetHash, VerificationScopeHash: binding.VerificationScopeHash,
		PolicyEnvelopeHash: binding.PolicyEnvelopeHash, PolicyVersion: binding.PolicyVersion, PolicyEpoch: binding.PolicyEpoch,
		Action: binding.Action, RequestingPrincipalID: binding.RequestingPrincipalID,
		AuthoritySource: binding.AuthoritySource, AuthorityVersion: binding.AuthorityVersion,
		AuthoritySnapshotHash: binding.AuthoritySnapshotHash, RequiredRole: binding.RequiredRole,
		Quorum: binding.Quorum, ServerIdentity: binding.ServerIdentity,
	}
}

func (r Record) validate() error {
	for _, field := range []struct {
		name  string
		value string
	}{
		{"approval_id", r.ApprovalID}, {"tenant_id", r.TenantID}, {"workspace_id", r.WorkspaceID},
	} {
		if !validToken(field.value) {
			return invalidRecord(field.name + " is invalid")
		}
	}
	if !r.State.valid() || r.HoldStartedAt.IsZero() || r.CreatedAt.IsZero() || r.UpdatedAt.IsZero() || r.Version <= 0 || !isUTC(r.HoldStartedAt) || !isUTC(r.CreatedAt) || !isUTC(r.UpdatedAt) || !r.CreatedAt.Equal(r.HoldStartedAt) || r.UpdatedAt.Before(r.CreatedAt) {
		return invalidRecord("record lifecycle timestamps are invalid")
	}
	if err := r.Binding.Validate(); err != nil || r.Binding.TenantID != r.TenantID || r.Binding.WorkspaceID != r.WorkspaceID {
		return invalidRecord("record binding is invalid or out of scope")
	}
	if r.Challenge != nil {
		if err := validateChallenge(r); err != nil {
			return err
		}
	}
	if r.ExpiresAt != nil && !isUTC(*r.ExpiresAt) {
		return invalidRecord("expires_at is not UTC")
	}
	if r.ConsumedAt != nil && !isUTC(*r.ConsumedAt) {
		return invalidRecord("consumed_at is not UTC")
	}
	switch r.State {
	case StateHoldPending:
		if r.Challenge != nil || r.QuorumVerifiedAt != nil || len(r.Assertions) != 0 || r.SignedGrant != nil || r.SignedConsumption != nil || r.ExpiresAt != nil || r.ConsumedAt != nil || r.ConsumedBy != "" || !r.UpdatedAt.Equal(r.HoldStartedAt) {
			return invalidRecord("hold pending artifacts are invalid")
		}
	case StateChallengeIssued:
		if r.Challenge == nil || r.QuorumVerifiedAt != nil || len(r.Assertions) != 0 || r.SignedGrant != nil || r.SignedConsumption != nil || r.ExpiresAt == nil || !r.ExpiresAt.Equal(r.Challenge.ExpiresAt) || !r.UpdatedAt.Equal(r.Challenge.IssuedAt) {
			return invalidRecord("challenge issued artifacts are invalid")
		}
	case StateQuorumVerified:
		if r.Challenge == nil || r.QuorumVerifiedAt == nil || len(r.Assertions) < r.Binding.Quorum || r.SignedGrant != nil || r.SignedConsumption != nil || r.ExpiresAt == nil || !r.ExpiresAt.Equal(r.Challenge.ExpiresAt) || !r.UpdatedAt.Equal(*r.QuorumVerifiedAt) || r.QuorumVerifiedAt.Before(r.Challenge.IssuedAt) || !r.QuorumVerifiedAt.Before(r.Challenge.ExpiresAt) {
			return invalidRecord("quorum verified artifacts are invalid")
		}
	case StateGrantIssued, StateConsumed:
		if err := validateGrantRecord(r); err != nil {
			return err
		}
		if r.State == StateConsumed {
			if r.SignedConsumption == nil || r.ConsumedAt == nil || !validToken(r.ConsumedBy) || !r.UpdatedAt.Equal(*r.ConsumedAt) || r.SignedConsumption.Consumption.ConsumedBy != r.ConsumedBy || !r.SignedConsumption.Consumption.ConsumedAt.Equal(*r.ConsumedAt) || r.SignedConsumption.Consumption.ValidateGrant(r.SignedGrant.Grant) != nil || !validSignature(r.SignedConsumption.Signature) || r.SignedConsumption.Algorithm != generatedspecapproval.SignatureAlgorithmEd25519 {
				return invalidRecord("consumed artifacts are invalid")
			}
		} else if r.SignedConsumption != nil || r.ConsumedAt != nil || r.ConsumedBy != "" {
			return invalidRecord("grant issued cannot contain consumption")
		}
	case StateDenied, StateExpired:
		if r.SignedConsumption != nil || r.ConsumedAt != nil || r.ConsumedBy != "" {
			return invalidRecord("terminal non-consumed state contains consumption")
		}
		if r.SignedGrant != nil {
			if err := validateGrantRecord(r); err != nil {
				return err
			}
		} else if r.Challenge != nil && (r.ExpiresAt == nil || !r.ExpiresAt.Equal(r.Challenge.ExpiresAt)) {
			return invalidRecord("terminal challenge expiry mismatch")
		}
		if r.State == StateExpired && (r.ExpiresAt == nil || r.UpdatedAt.Before(*r.ExpiresAt)) {
			return invalidRecord("expired before the committed lifetime")
		}
	}
	if r.State != StateConsumed && (r.SignedConsumption != nil || r.ConsumedAt != nil || r.ConsumedBy != "") {
		return invalidRecord("consumption fields require consumed state")
	}
	return nil
}

func validateChallenge(record Record) error {
	challenge := *record.Challenge
	if err := challenge.Validate(); err != nil {
		return invalidRecord("challenge: " + err.Error())
	}
	sealed, err := challenge.Seal()
	if err != nil || sealed.ChallengeHash != challenge.ChallengeHash {
		return invalidRecord("challenge integrity mismatch")
	}
	b := record.Binding
	if challenge.ApprovalID != record.ApprovalID || challenge.TenantID != record.TenantID || challenge.WorkspaceID != record.WorkspaceID || !challenge.HoldStartedAt.Equal(record.HoldStartedAt) ||
		challenge.Audience != b.Audience || challenge.GeneratedSpecID != b.GeneratedSpecID || challenge.GeneratedSpecHash != b.GeneratedSpecHash ||
		challenge.ExecutionPlanHash != b.ExecutionPlanHash || challenge.PlanTransactionHash != b.PlanTransactionHash || challenge.WriteSetHash != b.WriteSetHash ||
		challenge.VerificationScopeHash != b.VerificationScopeHash || challenge.PolicyEnvelopeHash != b.PolicyEnvelopeHash || challenge.PolicyVersion != b.PolicyVersion ||
		challenge.PolicyEpoch != b.PolicyEpoch || challenge.Action != b.Action || challenge.RequestingPrincipalID != b.RequestingPrincipalID ||
		challenge.AuthoritySource != b.AuthoritySource || challenge.AuthorityVersion != b.AuthorityVersion || challenge.AuthoritySnapshotHash != b.AuthoritySnapshotHash ||
		challenge.RequiredRole != b.RequiredRole || challenge.Quorum != b.Quorum || challenge.ServerIdentity != b.ServerIdentity {
		return invalidRecord("challenge does not match immutable binding")
	}
	return nil
}

func validateGrantRecord(record Record) error {
	if record.Challenge == nil || record.QuorumVerifiedAt == nil || len(record.Assertions) < record.Binding.Quorum || record.SignedGrant == nil || record.ExpiresAt == nil {
		return invalidRecord("grant record chain is incomplete")
	}
	grant := record.SignedGrant.Grant
	if err := grant.Validate(); err != nil {
		return invalidRecord("grant: " + err.Error())
	}
	sealed, err := grant.Seal()
	if err != nil || sealed.GrantHash != grant.GrantHash || !validSignature(record.SignedGrant.Signature) || record.SignedGrant.Algorithm != generatedspecapproval.SignatureAlgorithmEd25519 || !record.UpdatedAt.Equal(grant.IssuedAt) && record.State == StateGrantIssued {
		return invalidRecord("signed grant integrity is invalid")
	}
	challenge := *record.Challenge
	if grant.ApprovalID != record.ApprovalID || grant.TenantID != record.TenantID || grant.WorkspaceID != record.WorkspaceID ||
		grant.Audience != challenge.Audience || grant.GeneratedSpecID != challenge.GeneratedSpecID || grant.GeneratedSpecHash != challenge.GeneratedSpecHash ||
		grant.ExecutionPlanHash != challenge.ExecutionPlanHash || grant.PlanTransactionHash != challenge.PlanTransactionHash || grant.WriteSetHash != challenge.WriteSetHash ||
		grant.VerificationScopeHash != challenge.VerificationScopeHash || grant.PolicyEnvelopeHash != challenge.PolicyEnvelopeHash || grant.PolicyVersion != challenge.PolicyVersion ||
		grant.PolicyEpoch != challenge.PolicyEpoch || grant.Action != challenge.Action || grant.RequestingPrincipalID != challenge.RequestingPrincipalID ||
		grant.ChallengeHash != challenge.ChallengeHash || grant.AuthoritySource != challenge.AuthoritySource || grant.AuthorityVersion != challenge.AuthorityVersion ||
		grant.AuthoritySnapshotHash != challenge.AuthoritySnapshotHash || grant.ServerIdentity != challenge.ServerIdentity || grant.IssuedAt.Before(*record.QuorumVerifiedAt) || grant.ExpiresAt.After(challenge.ExpiresAt) || !record.ExpiresAt.Equal(grant.ExpiresAt) {
		return invalidRecord("grant does not match verified challenge")
	}
	return nil
}

func (s State) valid() bool {
	switch s {
	case StateHoldPending, StateChallengeIssued, StateQuorumVerified, StateGrantIssued, StateConsumed, StateDenied, StateExpired:
		return true
	default:
		return false
	}
}

func validToken(value string) bool {
	return value != "" && strings.IndexFunc(value, unicode.IsSpace) == -1
}

func validSHA256(value string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	raw := strings.TrimPrefix(value, prefix)
	if len(raw) != 64 || strings.ToLower(raw) != raw {
		return false
	}
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == 32
}

func validSignature(value string) bool {
	if len(value) != 128 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 64
}

func isUTC(value time.Time) bool {
	_, offset := value.Zone()
	return offset == 0
}

func invalidRecord(message string) error { return fmt.Errorf("%w: %s", ErrInvalidRecord, message) }
