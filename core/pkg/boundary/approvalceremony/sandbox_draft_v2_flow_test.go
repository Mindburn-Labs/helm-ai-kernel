package approvalceremony

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestV2SandboxDraftCeremonyLifecycle(t *testing.T) {
	hold, _, _, grantTemplate := ceremonyFixtures(t)
	hold.Spec.ApprovalGrantSchemaVersion = contracts.ApprovalGrantSchemaV2
	hold.Spec.Audience = contracts.ApprovalGrantAudiencePolicyDraftSandboxExecutorV1
	hold.Spec.PackID = contracts.ApprovalGrantPackIDPolicyDraftSandbox
	hold.Spec.Action = contracts.ApprovalGrantActionPolicyDraftSandbox

	authority, approverKeys := approvalTestAuthority(hold.Spec, hold.HoldStartedAt)
	signer := crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize)), "approval-v2-sandbox-test")
	store := &sandboxDraftV2FlowStore{}
	consumer := &staticConsumerProvider{identity: consumerForSpec(hold.Spec)}
	config := serviceTestConfig(hold.Spec, grantTemplate)
	now := hold.HoldStartedAt
	service, err := newService(
		store,
		&staticBindingProvider{spec: hold.Spec},
		&staticAuthorityProvider{store: authority},
		&staticControlProvider{identity: controlForSpec(hold.Spec)},
		consumer,
		signer,
		func() time.Time { return now },
		bytes.NewReader(bytes.Repeat([]byte{9}, 1024)),
		config,
	)
	if err != nil {
		t.Fatal(err)
	}

	held, err := service.BeginHold(context.Background(), hold.Spec.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold(): %v", err)
	}
	if held.State != StateHoldPending || held.Spec.ApprovalGrantSchemaVersion != contracts.ApprovalGrantSchemaV2 {
		t.Fatalf("held record = %+v", held)
	}

	if _, err := service.IssueChallenge(context.Background(), held.ApprovalID); !errors.Is(err, ErrHoldPending) {
		t.Fatalf("early IssueChallenge() error = %v, want %v", err, ErrHoldPending)
	}

	now = held.HoldStartedAt.Add(config.MinHoldDuration)
	challenged, err := service.IssueChallenge(context.Background(), held.ApprovalID)
	if err != nil {
		t.Fatalf("IssueChallenge(): %v", err)
	}
	if challenged.Challenge == nil || challenged.State != StateChallengeIssued {
		t.Fatalf("issue challenge record = %+v", challenged)
	}
	if challenged.Challenge.Domain != contracts.ApprovalChallengeDomainV2 ||
		challenged.Challenge.SchemaVersion != contracts.ApprovalChallengeSchemaV2 ||
		challenged.Challenge.ContractVersion != contracts.ApprovalChallengeContractV2 {
		t.Fatalf("challenge envelope = %+v", challenged.Challenge)
	}
	if challenged.Challenge.Audience != hold.Spec.Audience ||
		challenged.Challenge.PackID != hold.Spec.PackID ||
		challenged.Challenge.Action != hold.Spec.Action {
		t.Fatalf("challenge tuple mutation = %+v", challenged.Challenge)
	}

	assertions := approvalTestAssertions(t, *challenged.Challenge, approverKeys)
	now = now.Add(time.Minute)
	verified, err := service.VerifyQuorum(context.Background(), held.ApprovalID, assertions)
	if err != nil {
		t.Fatalf("VerifyQuorum(): %v", err)
	}
	if verified.VerifiedRef == nil {
		t.Fatalf("verify quorum record = %+v", verified)
	}
	if verified.VerifiedRef.Audience != challenged.Challenge.Audience ||
		verified.VerifiedRef.PackID != challenged.Challenge.PackID ||
		verified.VerifiedRef.Action != challenged.Challenge.Action ||
		verified.VerifiedRef.PackManifestHash != challenged.Challenge.PackManifestHash {
		t.Fatalf("verified tuple mutation = %+v", verified.VerifiedRef)
	}

	now = now.Add(time.Minute)
	granted, err := service.IssueGrant(context.Background(), held.ApprovalID)
	if err != nil {
		t.Fatalf("IssueGrant(): %v", err)
	}
	if granted.State != StateGrantIssued || granted.Grant == nil {
		t.Fatalf("issued grant record = %+v", granted)
	}
	if granted.Grant.SchemaVersion != contracts.ApprovalGrantSchemaV2 ||
		granted.Grant.ContractVersion != contracts.ApprovalGrantContractV2 {
		t.Fatalf("grant envelope = %+v", granted.Grant)
	}
	if granted.GrantSignatureAlgorithm != GrantSignatureEd25519 || granted.GrantSignature == "" {
		t.Fatalf("grant signature envelope = %+v", granted)
	}
	if granted.Grant.Audience != hold.Spec.Audience ||
		granted.Grant.PackID != hold.Spec.PackID ||
		granted.Grant.Action != hold.Spec.Action {
		t.Fatalf("grant tuple mutation = %+v", granted.Grant)
	}
	if granted.Grant.CeremonyHash == "" {
		t.Fatalf("grant signature mismatch = %+v", granted.Grant)
	}

	if _, err := service.IssueChallenge(context.Background(), held.ApprovalID); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("second IssueChallenge() error = %v, want %v", err, ErrTransitionConflict)
	}
	if _, err := service.IssueGrant(context.Background(), held.ApprovalID); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("second IssueGrant() error = %v, want %v", err, ErrTransitionConflict)
	}

	consumer.identity.Audience = "helm-data-plane-invalid"
	if _, err := service.ConsumeGrant(context.Background(), held.ApprovalID, granted.Grant.GrantID, granted.Grant.GrantHash, granted.Grant.Nonce); !errors.Is(err, ErrConsumerUnavailable) {
		t.Fatalf("wrong-audience ConsumeGrant() error = %v, want %v", err, ErrConsumerUnavailable)
	}
	if store.record.State != StateGrantIssued || store.consumeCalls != 0 {
		t.Fatalf("wrong-audience consumption changed record = %+v calls=%d", store.record, store.consumeCalls)
	}

	consumer.identity.Audience = hold.Spec.Audience
	consumed, err := service.ConsumeGrant(
		context.Background(),
		held.ApprovalID,
		granted.Grant.GrantID,
		granted.Grant.GrantHash,
		granted.Grant.Nonce,
	)
	if err != nil {
		t.Fatalf("ConsumeGrant(): %v", err)
	}
	if consumed.State != StateConsumed {
		t.Fatalf("consumed record = %+v", consumed)
	}
	if consumed.Grant == nil || consumed.GrantConsumption == nil {
		t.Fatalf("consumed envelopes = %+v", consumed)
	}
	if consumed.Grant.SchemaVersion != contracts.ApprovalGrantSchemaV2 ||
		consumed.Grant.ContractVersion != contracts.ApprovalGrantContractV2 {
		t.Fatalf("consumed grant envelope = %+v", consumed.Grant)
	}
	if consumed.GrantConsumption.SchemaVersion != contracts.ApprovalGrantConsumptionSchemaV2 ||
		consumed.GrantConsumption.ContractVersion != contracts.ApprovalGrantConsumptionContractV2 {
		t.Fatalf("consumed consumption envelope = %+v", consumed.GrantConsumption)
	}
	if consumed.GrantConsumption.Audience != hold.Spec.Audience ||
		consumed.GrantConsumption.PackID != hold.Spec.PackID ||
		consumed.GrantConsumption.Action != hold.Spec.Action {
		t.Fatalf("consumption tuple mutation = %+v", consumed.GrantConsumption)
	}
	if consumed.GrantConsumption.ConsumedBy != consumer.identity.Subject ||
		consumed.ConsumedBy != consumer.identity.Subject {
		t.Fatalf("consumer identity not propagated = %+v", consumed)
	}

	commitment, err := CeremonyCommitment(withVerified(withChallenge(held, *challenged.Challenge), *verified.VerifiedRef))
	if err != nil {
		t.Fatalf("CeremonyCommitment(): %v", err)
	}
	if granted.Grant.CeremonyHash != commitment {
		t.Fatalf("ceremony commitment mismatch: %s != %s", granted.Grant.CeremonyHash, commitment)
	}

	if _, err := service.ConsumeGrant(context.Background(), held.ApprovalID, granted.Grant.GrantID, granted.Grant.GrantHash, granted.Grant.Nonce); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("second ConsumeGrant() error = %v, want %v", err, ErrTransitionConflict)
	}
	if consumed.Version != store.record.Version {
		t.Fatalf("version advanced after replayed consume: record=%d consumed=%d", store.record.Version, consumed.Version)
	}
}

type sandboxDraftV2FlowStore struct {
	record              Record
	createCalls         int
	issueChallengeCalls int
	verifyCalls         int
	issueGrantCalls     int
	consumeCalls        int
}

func (s *sandboxDraftV2FlowStore) createHold(_ context.Context, record Record) (Record, error) {
	s.createCalls++
	if s.record.ApprovalID != "" {
		return Record{}, ErrTransitionConflict
	}
	if err := record.Validate(); err != nil {
		return Record{}, err
	}
	s.record = record
	return s.record, nil
}

func (s *sandboxDraftV2FlowStore) get(_ context.Context, _, _, approvalID string) (Record, error) {
	if s.record.ApprovalID == "" {
		return Record{}, ErrNotFound
	}
	if s.record.ApprovalID != approvalID {
		return Record{}, ErrNotFound
	}
	return s.record, nil
}

func (s *sandboxDraftV2FlowStore) issueChallenge(_ context.Context, _, _, _ string, challenge contracts.ApprovalChallenge, now time.Time) (Record, error) {
	s.issueChallengeCalls++
	if s.record.State != StateHoldPending {
		return Record{}, ErrTransitionConflict
	}
	s.record.Challenge = &challenge
	s.record.State = StateChallengeIssued
	s.record.UpdatedAt = now
	expiresAt := s.record.Challenge.ExpiresAt
	s.record.ExpiresAt = &expiresAt
	s.record.Version++
	s.record.VerifiedRef = nil
	s.record.Grant = nil
	s.record.GrantSignature = ""
	s.record.GrantSignatureAlgorithm = ""
	if err := s.record.Validate(); err != nil {
		return Record{}, err
	}
	return s.record, nil
}

func (s *sandboxDraftV2FlowStore) recordQuorum(_ context.Context, _, _, _ string, verified approvalverify.VerifiedApprovalRef, _ time.Time) (Record, error) {
	s.verifyCalls++
	if s.record.State != StateChallengeIssued || s.record.Challenge == nil {
		return Record{}, ErrTransitionConflict
	}
	if verified.ChallengeID != s.record.Challenge.ChallengeID || verified.ChallengeHash != s.record.Challenge.ChallengeHash {
		return Record{}, ErrTransitionConflict
	}
	s.record.VerifiedRef = &verified
	s.record.State = StateQuorumVerified
	s.record.UpdatedAt = s.record.VerifiedRef.VerifiedAt
	s.record.Version++
	if err := s.record.Validate(); err != nil {
		return Record{}, err
	}
	return s.record, nil
}

func (s *sandboxDraftV2FlowStore) issueGrant(_ context.Context, _, _, _ string, grant contracts.ApprovalGrant, algorithm, signature string, now time.Time) (Record, error) {
	s.issueGrantCalls++
	if s.record.State != StateQuorumVerified || s.record.VerifiedRef == nil || s.record.Challenge == nil {
		return Record{}, ErrTransitionConflict
	}
	s.record.VerifiedRef.SignerSetHash = grant.SignerSetHash
	if grant.Audience != s.record.VerifiedRef.Audience || grant.PackID != s.record.VerifiedRef.PackID {
		return Record{}, ErrTransitionConflict
	}
	s.record.Grant = &grant
	s.record.GrantSignatureAlgorithm = algorithm
	s.record.GrantSignature = signature
	if s.record.Grant == nil {
		return Record{}, ErrTransitionConflict
	}
	s.record.State = StateGrantIssued
	s.record.UpdatedAt = now
	expiresAt := s.record.Grant.ExpiresAt
	s.record.ExpiresAt = &expiresAt
	s.record.Version++
	s.record.ConsumedBy = ""
	s.record.ConsumedAt = nil
	s.record.GrantConsumption = nil
	if err := s.record.Validate(); err != nil {
		return Record{}, err
	}
	return s.record, nil
}

func (s *sandboxDraftV2FlowStore) consumeGrant(
	_ context.Context, _, _, approvalID, grantID, grantHash, nonce string,
	consumption contracts.ApprovalGrantConsumption,
	algorithm, signature string,
	now time.Time,
) (Record, error) {
	s.consumeCalls++
	if s.record.State != StateGrantIssued || s.record.Grant == nil {
		return Record{}, ErrTransitionConflict
	}
	if approvalID != s.record.ApprovalID || grantID != s.record.Grant.GrantID || grantHash != s.record.Grant.GrantHash || nonce != s.record.Grant.Nonce {
		return Record{}, ErrTransitionConflict
	}
	s.record.State = StateConsumed
	s.record.ConsumedAt = &now
	s.record.ConsumedBy = consumption.ConsumedBy
	s.record.GrantConsumption = &consumption
	s.record.ConsumptionSignatureAlgorithm = algorithm
	s.record.ConsumptionSignature = signature
	s.record.UpdatedAt = now
	s.record.Version++
	if err := s.record.Validate(); err != nil {
		return Record{}, err
	}
	return s.record, nil
}

func (*sandboxDraftV2FlowStore) deny(context.Context, string, string, string, time.Time) (Record, error) {
	return Record{}, ErrTransitionConflict
}

func (*sandboxDraftV2FlowStore) expire(context.Context, string, string, string, time.Time) (Record, error) {
	return Record{}, ErrTransitionConflict
}
