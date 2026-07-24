// quantum_posture: GeneratedSpec approval ceremony tests exercise classical
// Ed25519 ceremony and grant signatures only; they do not establish hybrid or
// post-quantum ceremony support.
package generatedspecapprovalceremony

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapproval"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestLifecycleAndSameIdentityRecovery(t *testing.T) {
	fixture := newCeremonyFixture(t)
	ctx := context.Background()

	hold, err := fixture.service.BeginHold(ctx, fixture.binding.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold() error = %v", err)
	}
	if hold.State != StateHoldPending || hold.TenantID != fixture.control.identity.TenantID || hold.WorkspaceID != fixture.control.identity.WorkspaceID {
		t.Fatalf("BeginHold() record = %+v, want source-owned hold scope", hold)
	}
	if _, err := fixture.service.IssueChallenge(ctx, hold.ApprovalID); !errors.Is(err, ErrHoldPending) {
		t.Fatalf("IssueChallenge(before hold) error = %v, want hold pending", err)
	}

	fixture.advance(fixture.config.MinHoldDuration)
	challenged, err := fixture.service.IssueChallenge(ctx, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueChallenge() error = %v", err)
	}
	if challenged.State != StateChallengeIssued || challenged.Challenge == nil {
		t.Fatalf("IssueChallenge() record = %+v, want issued challenge", challenged)
	}
	assertChallengeBinding(t, fixture.binding, *challenged.Challenge)

	assertion := fixture.assertion(t, *challenged.Challenge)
	quorum, err := fixture.service.VerifyQuorum(ctx, hold.ApprovalID, []contracts.GeneratedSpecApprovalAssertion{assertion})
	if err != nil {
		t.Fatalf("VerifyQuorum() error = %v", err)
	}
	if quorum.State != StateQuorumVerified || quorum.QuorumVerifiedAt == nil || len(quorum.Assertions) != 1 {
		t.Fatalf("VerifyQuorum() record = %+v, want stored raw quorum assertions", quorum)
	}

	granted, err := fixture.service.IssueGrant(ctx, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueGrant() error = %v", err)
	}
	if granted.State != StateGrantIssued || granted.SignedGrant == nil {
		t.Fatalf("IssueGrant() record = %+v, want signed grant", granted)
	}
	if err := fixture.verifier.VerifyGrant(*granted.SignedGrant, fixture.now); err != nil {
		t.Fatalf("VerifyGrant() error = %v", err)
	}

	consumed, err := fixture.service.ConsumeGrant(ctx, hold.ApprovalID, granted.SignedGrant.Grant.GrantID, granted.SignedGrant.Grant.GrantHash, granted.SignedGrant.Grant.Nonce)
	if err != nil {
		t.Fatalf("ConsumeGrant() error = %v", err)
	}
	if consumed.State != StateConsumed || consumed.ConsumedBy != fixture.consumer.identity.Subject || consumed.SignedConsumption == nil {
		t.Fatalf("ConsumeGrant() record = %+v, want source-owned consumption identity", consumed)
	}
	if err := fixture.verifier.VerifyConsumption(*consumed.SignedConsumption, *consumed.SignedGrant); err != nil {
		t.Fatalf("VerifyConsumption() error = %v", err)
	}

	recovered, err := fixture.service.RecoverGrantConsumption(ctx, hold.ApprovalID, granted.SignedGrant.Grant.GrantID, granted.SignedGrant.Grant.GrantHash, granted.SignedGrant.Grant.Nonce)
	if err != nil {
		t.Fatalf("RecoverGrantConsumption() error = %v", err)
	}
	if recovered.Version != consumed.Version || !recovered.ConsumedAt.Equal(*consumed.ConsumedAt) || recovered.SignedConsumption.Consumption.ConsumptionHash != consumed.SignedConsumption.Consumption.ConsumptionHash {
		t.Fatalf("RecoverGrantConsumption() = %+v, want exact persisted consumption", recovered)
	}
}

func TestIssueGrantRevalidatesRawAssertionsAgainstAuthoritySnapshot(t *testing.T) {
	fixture := newCeremonyFixture(t)
	ctx := context.Background()
	quorum := fixture.toQuorum(t, ctx)

	key := fixture.authority.store.Keys[fixture.keyID]
	key.Enabled = false
	fixture.authority.store.Keys[fixture.keyID] = key
	if _, err := fixture.service.IssueGrant(ctx, quorum.ApprovalID); !errors.Is(err, generatedspecapproval.ErrAuthorityRejected) {
		t.Fatalf("IssueGrant() after authority key revocation error = %v, want authority rejection", err)
	}
}

func TestVerifyQuorumRejectsRequesterAndChallengeMismatch(t *testing.T) {
	t.Run("requester self approval", func(t *testing.T) {
		fixture := newCeremonyFixture(t)
		ctx := context.Background()
		challenged := fixture.toChallenge(t, ctx)
		key := fixture.authority.store.Keys[fixture.keyID]
		key.PrincipalID = fixture.binding.RequestingPrincipalID
		fixture.authority.store.Keys[fixture.keyID] = key
		if _, err := fixture.service.VerifyQuorum(ctx, challenged.ApprovalID, []contracts.GeneratedSpecApprovalAssertion{fixture.assertion(t, *challenged.Challenge)}); !errors.Is(err, generatedspecapproval.ErrAuthorityRejected) {
			t.Fatalf("VerifyQuorum(self approval) error = %v, want authority rejection", err)
		}
	})

	t.Run("assertion replayed from another challenge", func(t *testing.T) {
		fixture := newCeremonyFixture(t)
		ctx := context.Background()
		challenged := fixture.toChallenge(t, ctx)
		assertion := fixture.assertion(t, *challenged.Challenge)
		assertion.ChallengeHash = testHash("9")
		if _, err := fixture.service.VerifyQuorum(ctx, challenged.ApprovalID, []contracts.GeneratedSpecApprovalAssertion{assertion}); !errors.Is(err, generatedspecapproval.ErrVerificationFailed) {
			t.Fatalf("VerifyQuorum(mismatched challenge) error = %v, want verification failure", err)
		}
	})
}

func TestVerifyQuorumRejectsResealedChallengeBeyondConfiguredTTL(t *testing.T) {
	fixture := newCeremonyFixture(t)
	ctx := context.Background()
	challenged := fixture.toChallenge(t, ctx)

	// Simulate a store-level reseal that extends the persisted challenge expiry
	// past the configured per-issuance ChallengeTTL while keeping the challenge
	// inside its maximum lifetime, then verify with assertions bound to the
	// resealed hash. Verification must still reject the extended TTL.
	var resealed contracts.GeneratedSpecApprovalChallenge
	fixture.mutate(challenged.ApprovalID, func(record *Record) {
		updated := *record.Challenge
		updated.ExpiresAt = updated.IssuedAt.Add(fixture.config.ChallengeTTL + time.Minute)
		sealed, sealErr := updated.Seal()
		if sealErr != nil {
			t.Errorf("Seal() error = %v", sealErr)
			return
		}
		record.Challenge = &sealed
		record.ExpiresAt = &sealed.ExpiresAt
		resealed = sealed
	})
	if resealed.ChallengeHash == challenged.Challenge.ChallengeHash {
		t.Fatal("resealed challenge must carry a new challenge hash")
	}
	if _, err := fixture.service.VerifyQuorum(ctx, challenged.ApprovalID, []contracts.GeneratedSpecApprovalAssertion{fixture.assertion(t, resealed)}); !errors.Is(err, generatedspecapproval.ErrVerificationFailed) {
		t.Fatalf("VerifyQuorum(resealed challenge) error = %v, want verification failure", err)
	}
}

func TestMemoryStoreCreateHoldRejectsNonHoldRecords(t *testing.T) {
	fixture := newCeremonyFixture(t)
	ctx := context.Background()
	hold, err := fixture.service.BeginHold(ctx, fixture.binding.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold() error = %v", err)
	}
	hold.ApprovalID = "approval-forged"
	hold.State = StateChallengeIssued
	if _, err := fixture.store.CreateHold(ctx, hold); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("CreateHold(non-hold record) error = %v, want transition conflict", err)
	}
}

func TestConsumeRejectsWrongConsumerAndReplay(t *testing.T) {
	fixture := newCeremonyFixture(t)
	ctx := context.Background()
	granted := fixture.toGrant(t, ctx)
	grant := granted.SignedGrant.Grant

	fixture.consumer.identity.Audience = "wrong-audience"
	if _, err := fixture.service.ConsumeGrant(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); !errors.Is(err, ErrConsumerUnavailable) {
		t.Fatalf("ConsumeGrant(wrong consumer audience) error = %v, want consumer rejection", err)
	}
	fixture.consumer.identity.Audience = contracts.GeneratedSpecApprovalAudienceV1
	consumed, err := fixture.service.ConsumeGrant(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce)
	if err != nil {
		t.Fatalf("ConsumeGrant() error = %v", err)
	}
	if _, err := fixture.service.ConsumeGrant(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("ConsumeGrant(replay) error = %v, want transition conflict", err)
	}

	fixture.consumer.identity.Subject = "spiffe://helm/control-plane-b"
	if _, err := fixture.service.RecoverGrantConsumption(ctx, consumed.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); !errors.Is(err, ErrConsumerUnavailable) {
		t.Fatalf("RecoverGrantConsumption(other identity) error = %v, want consumer rejection", err)
	}
}

func TestConsumeGrantSealerPinsCallerScope(t *testing.T) {
	newTamperedService := func(t *testing.T, fixture *ceremonyFixture, tamper func(*generatedspecapproval.SignedGrant, *string, *time.Time)) *Service {
		t.Helper()
		svc, err := newService(
			tamperedSealerStore{Store: fixture.store, tamper: tamper},
			bindingStub{binding: fixture.binding}, fixture.authority, fixture.control, fixture.consumer,
			fixture.signer, fixture.verifier, func() time.Time { return fixture.now },
			bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)), fixture.config)
		if err != nil {
			t.Fatalf("newService() error = %v", err)
		}
		return svc
	}

	t.Run("substituted consumer", func(t *testing.T) {
		fixture := newCeremonyFixture(t)
		ctx := context.Background()
		granted := fixture.toGrant(t, ctx)
		grant := granted.SignedGrant.Grant
		svc := newTamperedService(t, fixture, func(_ *generatedspecapproval.SignedGrant, consumedBy *string, _ *time.Time) {
			*consumedBy = "spiffe://helm/control-plane-mallory"
		})
		if _, err := svc.ConsumeGrant(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); !errors.Is(err, ErrConsumerUnavailable) {
			t.Fatalf("ConsumeGrant(substituted consumer) error = %v, want consumer rejection", err)
		}
	})

	t.Run("substituted timestamp", func(t *testing.T) {
		fixture := newCeremonyFixture(t)
		ctx := context.Background()
		granted := fixture.toGrant(t, ctx)
		grant := granted.SignedGrant.Grant
		svc := newTamperedService(t, fixture, func(_ *generatedspecapproval.SignedGrant, _ *string, consumedAt *time.Time) {
			*consumedAt = consumedAt.Add(-time.Minute)
		})
		if _, err := svc.ConsumeGrant(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); !errors.Is(err, ErrConsumerUnavailable) {
			t.Fatalf("ConsumeGrant(substituted timestamp) error = %v, want consumer rejection", err)
		}
	})

	t.Run("substituted grant", func(t *testing.T) {
		fixture := newCeremonyFixture(t)
		ctx := context.Background()
		granted := fixture.toGrant(t, ctx)
		grant := granted.SignedGrant.Grant
		svc := newTamperedService(t, fixture, func(signed *generatedspecapproval.SignedGrant, _ *string, _ *time.Time) {
			signed.Grant.Nonce = strings.Repeat("f", 64)
		})
		if _, err := svc.ConsumeGrant(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); !errors.Is(err, ErrConsumerUnavailable) {
			t.Fatalf("ConsumeGrant(substituted grant) error = %v, want consumer rejection", err)
		}
	})
}

func TestDenyFencesAnIssuedGrant(t *testing.T) {
	fixture := newCeremonyFixture(t)
	ctx := context.Background()
	granted := fixture.toGrant(t, ctx)
	grant := granted.SignedGrant.Grant

	denied, err := fixture.service.Deny(ctx, granted.ApprovalID)
	if err != nil {
		t.Fatalf("Deny() error = %v", err)
	}
	if denied.State != StateDenied {
		t.Fatalf("Deny() state = %s, want %s", denied.State, StateDenied)
	}
	if _, err := fixture.service.ConsumeGrant(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("ConsumeGrant(denied) error = %v, want transition conflict", err)
	}
}

func TestExpiryFailsClosedForConsumption(t *testing.T) {
	t.Run("unconsumed grant", func(t *testing.T) {
		fixture := newCeremonyFixture(t)
		ctx := context.Background()
		granted := fixture.toGrant(t, ctx)
		grant := granted.SignedGrant.Grant
		fixture.now = grant.ExpiresAt
		if _, err := fixture.service.ConsumeGrant(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); !errors.Is(err, ErrExpired) {
			t.Fatalf("ConsumeGrant(expired) error = %v, want expiry", err)
		}
		expired, err := fixture.service.Expire(ctx, granted.ApprovalID)
		if err != nil {
			t.Fatalf("Expire() error = %v", err)
		}
		if expired.State != StateExpired {
			t.Fatalf("Expire() state = %s, want %s", expired.State, StateExpired)
		}
	})
}

func TestRecoverGrantConsumptionServesPersistedReceiptAfterGrantExpiry(t *testing.T) {
	fixture := newCeremonyFixture(t)
	ctx := context.Background()
	granted := fixture.toGrant(t, ctx)
	grant := granted.SignedGrant.Grant
	consumed, err := fixture.service.ConsumeGrant(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce)
	if err != nil {
		t.Fatalf("ConsumeGrant() error = %v", err)
	}
	// The grant lapses after consumption was recorded; the same workload must
	// still be able to recover its persisted receipt.
	fixture.now = grant.ExpiresAt
	recovered, err := fixture.service.RecoverGrantConsumption(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce)
	if err != nil {
		t.Fatalf("RecoverGrantConsumption(after grant expiry) error = %v, want persisted receipt", err)
	}
	if recovered.State != StateConsumed || recovered.SignedConsumption.Consumption.ConsumptionHash != consumed.SignedConsumption.Consumption.ConsumptionHash {
		t.Fatalf("RecoverGrantConsumption() = %+v, want exact persisted consumption", recovered)
	}
}

func TestExpireReleasesHoldAfterMaxChallengeLifetime(t *testing.T) {
	fixture := newCeremonyFixture(t)
	ctx := context.Background()
	hold, err := fixture.service.BeginHold(ctx, fixture.binding.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold() error = %v", err)
	}
	if _, err := fixture.service.Expire(ctx, hold.ApprovalID); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("Expire(before challenge lifetime) error = %v, want transition conflict", err)
	}
	fixture.advance(fixture.config.MaxChallengeLifetime)
	if _, err := fixture.service.IssueChallenge(ctx, hold.ApprovalID); !errors.Is(err, ErrExpired) {
		t.Fatalf("IssueChallenge(after challenge lifetime) error = %v, want expiry", err)
	}
	expired, err := fixture.service.Expire(ctx, hold.ApprovalID)
	if err != nil {
		t.Fatalf("Expire() error = %v", err)
	}
	if expired.State != StateExpired {
		t.Fatalf("Expire() state = %s, want %s", expired.State, StateExpired)
	}
	if expired.ExpiresAt == nil || !expired.ExpiresAt.Equal(hold.HoldStartedAt.Add(fixture.config.MaxChallengeLifetime)) {
		t.Fatalf("Expire() expires_at = %v, want committed challenge lifetime deadline", expired.ExpiresAt)
	}
}

func TestStoredEnvelopesRequirePinnedSignatureVerification(t *testing.T) {
	t.Run("grant", func(t *testing.T) {
		fixture := newCeremonyFixture(t)
		ctx := context.Background()
		granted := fixture.toGrant(t, ctx)
		grant := granted.SignedGrant.Grant
		fixture.mutate(granted.ApprovalID, func(record *Record) {
			record.SignedGrant.Signature = strings.Repeat("0", 128)
		})
		if _, err := fixture.service.ConsumeGrant(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); !errors.Is(err, generatedspecapproval.ErrSignatureRejected) {
			t.Fatalf("ConsumeGrant(tampered stored grant) error = %v, want signature rejection", err)
		}
	})

	t.Run("consumption", func(t *testing.T) {
		fixture := newCeremonyFixture(t)
		ctx := context.Background()
		granted := fixture.toGrant(t, ctx)
		grant := granted.SignedGrant.Grant
		if _, err := fixture.service.ConsumeGrant(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); err != nil {
			t.Fatalf("ConsumeGrant() error = %v", err)
		}
		fixture.mutate(granted.ApprovalID, func(record *Record) {
			record.SignedConsumption.Signature = strings.Repeat("0", 128)
		})
		if _, err := fixture.service.RecoverGrantConsumption(ctx, granted.ApprovalID, grant.GrantID, grant.GrantHash, grant.Nonce); !errors.Is(err, generatedspecapproval.ErrSignatureRejected) {
			t.Fatalf("RecoverGrantConsumption(tampered stored consumption) error = %v, want signature rejection", err)
		}
	})
}

type ceremonyFixture struct {
	now        time.Time
	config     ServiceConfig
	binding    Binding
	store      *memoryStore
	authority  *authorityStub
	control    *controlStub
	consumer   *consumerStub
	service    *Service
	verifier   *generatedspecapproval.Ed25519Verifier
	signer     crypto.Signer
	privateKey ed25519.PrivateKey
	keyID      string
}

func newCeremonyFixture(t *testing.T) *ceremonyFixture {
	t.Helper()
	fixture := &ceremonyFixture{
		now: time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC),
		config: ServiceConfig{
			MinHoldDuration: time.Minute, ChallengeTTL: 4 * time.Minute, MaxChallengeLifetime: 8 * time.Minute,
			GrantTTL: 2 * time.Minute, MaxAssertions: 2, ServerIdentity: "spiffe://helm/kernel-a",
			KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/generated-spec-a",
		},
		binding: Binding{
			BindingRef: "binding-a", TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: contracts.GeneratedSpecApprovalAudienceV1,
			GeneratedSpecID: "spec-a", GeneratedSpecHash: testHash("a"), ExecutionPlanHash: testHash("b"),
			PlanTransactionHash: testHash("c"), WriteSetHash: testHash("d"), VerificationScopeHash: testHash("e"),
			PolicyEnvelopeHash: testHash("f"), PolicyVersion: "policy-v1", PolicyEpoch: "epoch-1", Action: contracts.GeneratedSpecApprovalActionV1,
			RequestingPrincipalID: "user:requester-a", AuthoritySource: "authority-a", AuthorityVersion: "version-a",
			AuthoritySnapshotHash: testHash("0"), RequiredRole: "generated-spec-approver", Quorum: 1, ServerIdentity: "spiffe://helm/kernel-a",
		},
		store:    newMemoryStore(8 * time.Minute),
		control:  &controlStub{identity: ControlIdentity{Subject: "spiffe://helm/control-api", TenantID: "tenant-a", WorkspaceID: "workspace-a"}},
		consumer: &consumerStub{identity: ConsumerIdentity{Subject: "spiffe://helm/control-plane-a", TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: contracts.GeneratedSpecApprovalAudienceV1}},
		keyID:    "approver-key-a",
	}
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	fixture.privateKey = privateKey
	fixture.authority = &authorityStub{store: approvalverify.TrustStore{
		AuthoritySource: fixture.binding.AuthoritySource, AuthorityVersion: fixture.binding.AuthorityVersion, AuthoritySnapshotHash: fixture.binding.AuthoritySnapshotHash,
		Keys: map[string]approvalverify.TrustedApproverKey{
			fixture.keyID: {
				KeyID: fixture.keyID, TenantID: fixture.binding.TenantID, PrincipalID: "user:approver-a", CredentialID: "credential-a", DeviceID: "device-a",
				PublicKey: publicKey, WorkspaceIDs: []string{fixture.binding.WorkspaceID}, Roles: []string{fixture.binding.RequiredRole},
				Actions: []string{fixture.binding.Action}, Audiences: []string{fixture.binding.Audience}, Enabled: true,
				NotBefore: fixture.now.Add(-time.Hour), NotAfter: fixture.now.Add(time.Hour),
			},
		},
	}}
	signer, err := crypto.NewEd25519Signer("generated-spec-kernel")
	if err != nil {
		t.Fatalf("NewEd25519Signer() error = %v", err)
	}
	fixture.signer = signer
	fixture.verifier, err = generatedspecapproval.NewEd25519Verifier(signer.PublicKeyBytes(), fixture.config.SigningKeyRef, fixture.config.KernelTrustRootID)
	if err != nil {
		t.Fatalf("NewEd25519Verifier() error = %v", err)
	}
	bindingProvider := bindingStub{binding: fixture.binding}
	fixture.service, err = newService(fixture.store, bindingProvider, fixture.authority, fixture.control, fixture.consumer, signer, fixture.verifier,
		func() time.Time { return fixture.now }, bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)), fixture.config)
	if err != nil {
		t.Fatalf("newService() error = %v", err)
	}
	return fixture
}

func (f *ceremonyFixture) advance(duration time.Duration) { f.now = f.now.Add(duration) }

func (f *ceremonyFixture) toChallenge(t *testing.T, ctx context.Context) Record {
	t.Helper()
	hold, err := f.service.BeginHold(ctx, f.binding.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold() error = %v", err)
	}
	f.advance(f.config.MinHoldDuration)
	challenged, err := f.service.IssueChallenge(ctx, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueChallenge() error = %v", err)
	}
	return challenged
}

func (f *ceremonyFixture) toQuorum(t *testing.T, ctx context.Context) Record {
	t.Helper()
	challenged := f.toChallenge(t, ctx)
	quorum, err := f.service.VerifyQuorum(ctx, challenged.ApprovalID, []contracts.GeneratedSpecApprovalAssertion{f.assertion(t, *challenged.Challenge)})
	if err != nil {
		t.Fatalf("VerifyQuorum() error = %v", err)
	}
	return quorum
}

func (f *ceremonyFixture) toGrant(t *testing.T, ctx context.Context) Record {
	t.Helper()
	quorum := f.toQuorum(t, ctx)
	granted, err := f.service.IssueGrant(ctx, quorum.ApprovalID)
	if err != nil {
		t.Fatalf("IssueGrant() error = %v", err)
	}
	return granted
}

func (f *ceremonyFixture) assertion(t *testing.T, challenge contracts.GeneratedSpecApprovalChallenge) contracts.GeneratedSpecApprovalAssertion {
	t.Helper()
	assertion := contracts.GeneratedSpecApprovalAssertion{
		Domain: contracts.GeneratedSpecApprovalAssertionDomainV1, SchemaVersion: contracts.GeneratedSpecApprovalAssertionSchemaV1,
		ContractVersion: contracts.GeneratedSpecApprovalAssertionContractV1, ChallengeID: challenge.ChallengeID, ChallengeHash: challenge.ChallengeHash,
		KeyID: f.keyID, Algorithm: contracts.GeneratedSpecApprovalAssertionEd25519,
	}
	digest, err := assertion.SigningDigest()
	if err != nil {
		t.Fatalf("SigningDigest() error = %v", err)
	}
	assertion.Signature = "ed25519:" + hex.EncodeToString(ed25519.Sign(f.privateKey, digest))
	return assertion
}

func (f *ceremonyFixture) mutate(approvalID string, mutate func(*Record)) {
	f.store.mu.Lock()
	defer f.store.mu.Unlock()
	key := keyFor(f.binding.TenantID, f.binding.WorkspaceID, approvalID)
	record := f.store.records[key]
	mutate(&record)
	f.store.records[key] = record
}

type bindingStub struct{ binding Binding }

func (s bindingStub) LoadGeneratedSpecApprovalBinding(_ context.Context, tenantID, workspaceID, bindingRef string) (Binding, error) {
	if tenantID != s.binding.TenantID || workspaceID != s.binding.WorkspaceID || bindingRef != s.binding.BindingRef {
		return Binding{}, fmt.Errorf("unexpected binding request")
	}
	return s.binding, nil
}

type authorityStub struct{ store approvalverify.TrustStore }

func (s *authorityStub) LoadGeneratedSpecApprovalAuthority(_ context.Context, tenantID, workspaceID, source, version, snapshotHash string) (approvalverify.TrustStore, error) {
	if tenantID == "" || workspaceID == "" || source != s.store.AuthoritySource || version != s.store.AuthorityVersion || snapshotHash != s.store.AuthoritySnapshotHash {
		return approvalverify.TrustStore{}, fmt.Errorf("unexpected authority request")
	}
	return s.store, nil
}

type controlStub struct{ identity ControlIdentity }

func (s *controlStub) LoadControlIdentity(context.Context) (ControlIdentity, error) {
	return s.identity, nil
}

type consumerStub struct{ identity ConsumerIdentity }

func (s *consumerStub) LoadConsumerIdentity(context.Context) (ConsumerIdentity, error) {
	return s.identity, nil
}

// tamperedSealerStore wraps a Store and rewrites the arguments handed to the
// consumption sealer, simulating a store that tries to use the sealer as a
// signing oracle for a substituted grant, consumer, or timestamp.
type tamperedSealerStore struct {
	Store
	tamper func(*generatedspecapproval.SignedGrant, *string, *time.Time)
}

func (s tamperedSealerStore) ConsumeGrant(ctx context.Context, tenantID, workspaceID, approvalID, grantID, grantHash, nonce, consumedBy, audience string, verifier GrantSignatureVerifier, consumedAt time.Time, seal ConsumptionSealer) (Record, error) {
	return s.Store.ConsumeGrant(ctx, tenantID, workspaceID, approvalID, grantID, grantHash, nonce, consumedBy, audience, verifier, consumedAt,
		func(signed generatedspecapproval.SignedGrant, by string, at time.Time) (generatedspecapproval.SignedConsumption, error) {
			s.tamper(&signed, &by, &at)
			return seal(signed, by, at)
		})
}

func assertChallengeBinding(t *testing.T, binding Binding, challenge contracts.GeneratedSpecApprovalChallenge) {
	t.Helper()
	if challenge.TenantID != binding.TenantID || challenge.WorkspaceID != binding.WorkspaceID || challenge.Audience != binding.Audience ||
		challenge.GeneratedSpecID != binding.GeneratedSpecID || challenge.GeneratedSpecHash != binding.GeneratedSpecHash ||
		challenge.ExecutionPlanHash != binding.ExecutionPlanHash || challenge.PlanTransactionHash != binding.PlanTransactionHash ||
		challenge.WriteSetHash != binding.WriteSetHash || challenge.VerificationScopeHash != binding.VerificationScopeHash ||
		challenge.PolicyEnvelopeHash != binding.PolicyEnvelopeHash || challenge.PolicyVersion != binding.PolicyVersion ||
		challenge.PolicyEpoch != binding.PolicyEpoch || challenge.Action != binding.Action || challenge.RequestingPrincipalID != binding.RequestingPrincipalID ||
		challenge.AuthoritySource != binding.AuthoritySource || challenge.AuthorityVersion != binding.AuthorityVersion ||
		challenge.AuthoritySnapshotHash != binding.AuthoritySnapshotHash || challenge.RequiredRole != binding.RequiredRole ||
		challenge.Quorum != binding.Quorum || challenge.ServerIdentity != binding.ServerIdentity {
		t.Fatalf("challenge did not exactly bind server-owned GeneratedSpec fields: %+v", challenge)
	}
}

func testHash(character string) string { return "sha256:" + strings.Repeat(character, 64) }
