// quantum_posture: GeneratedSpec approval tests exercise classical Ed25519
// grant and consumption signatures only; they do not establish hybrid or
// post-quantum approval support.
package generatedspecapproval

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

func TestVerifyIssueAndConsumeGeneratedSpecApproval(t *testing.T) {
	fixture := newApprovalFixture(t)
	verified, err := VerifyGeneratedSpecQuorum(fixture.challenge, []contracts.GeneratedSpecApprovalAssertion{fixture.assertion}, fixture.store, fixture.options, fixture.now)
	if err != nil {
		t.Fatalf("VerifyGeneratedSpecQuorum() error = %v", err)
	}
	kernelSigner, err := crypto.NewEd25519Signer("generated-spec-kernel")
	if err != nil {
		t.Fatalf("NewEd25519Signer() error = %v", err)
	}
	signedGrant, err := IssueGrant(fixture.challenge, verified, "grant-a", fixture.nonce("b"), kernelSigner, fixture.issuerConfig(), fixture.now.Add(time.Second))
	if err != nil {
		t.Fatalf("IssueGrant() error = %v", err)
	}
	verifier, err := NewEd25519Verifier(kernelSigner.PublicKeyBytes(), fixture.issuerConfig().SigningKeyRef, fixture.issuerConfig().KernelTrustRootID)
	if err != nil {
		t.Fatalf("NewEd25519Verifier() error = %v", err)
	}
	if err := verifier.VerifyGrant(signedGrant, signedGrant.Grant.IssuedAt); err != nil {
		t.Fatalf("VerifyGrant() error = %v", err)
	}

	consumption, err := NewConsumption(signedGrant.Grant, "spiffe://helm/control-plane-a", signedGrant.Grant.IssuedAt.Add(time.Second))
	if err != nil {
		t.Fatalf("NewConsumption() error = %v", err)
	}
	signedConsumption, err := SignConsumption(consumption, kernelSigner)
	if err != nil {
		t.Fatalf("SignConsumption() error = %v", err)
	}
	if err := verifier.VerifyConsumption(signedConsumption, signedGrant); err != nil {
		t.Fatalf("VerifyConsumption() error = %v", err)
	}
	unsignedGrant := signedGrant
	unsignedGrant.Signature = ""
	if err := verifier.VerifyConsumption(signedConsumption, unsignedGrant); !errors.Is(err, ErrSignatureRejected) {
		t.Fatalf("VerifyConsumption(unsigned grant) error = %v, want signature rejection", err)
	}
}

func TestGeneratedSpecApprovalRejectsRequesterAndBindingTamper(t *testing.T) {
	fixture := newApprovalFixture(t)
	selfKey := fixture.store.Keys[fixture.assertion.KeyID]
	selfKey.PrincipalID = fixture.challenge.RequestingPrincipalID
	fixture.store.Keys[fixture.assertion.KeyID] = selfKey
	if _, err := VerifyGeneratedSpecQuorum(fixture.challenge, []contracts.GeneratedSpecApprovalAssertion{fixture.assertion}, fixture.store, fixture.options, fixture.now); !errors.Is(err, ErrAuthorityRejected) {
		t.Fatalf("VerifyGeneratedSpecQuorum(self approval) error = %v, want authority rejected", err)
	}

	fixture = newApprovalFixture(t)
	fixture.options.Expected.WriteSetHash = hash("9")
	if _, err := VerifyGeneratedSpecQuorum(fixture.challenge, []contracts.GeneratedSpecApprovalAssertion{fixture.assertion}, fixture.store, fixture.options, fixture.now); !errors.Is(err, ErrVerificationFailed) {
		t.Fatalf("VerifyGeneratedSpecQuorum(write set mismatch) error = %v, want verification failed", err)
	}
}

func TestGeneratedSpecApprovalSignaturesRejectTampering(t *testing.T) {
	fixture := newApprovalFixture(t)
	verified, err := VerifyGeneratedSpecQuorum(fixture.challenge, []contracts.GeneratedSpecApprovalAssertion{fixture.assertion}, fixture.store, fixture.options, fixture.now)
	if err != nil {
		t.Fatalf("VerifyGeneratedSpecQuorum() error = %v", err)
	}
	kernelSigner, err := crypto.NewEd25519Signer("generated-spec-kernel")
	if err != nil {
		t.Fatalf("NewEd25519Signer() error = %v", err)
	}
	signedGrant, err := IssueGrant(fixture.challenge, verified, "grant-a", fixture.nonce("b"), kernelSigner, fixture.issuerConfig(), fixture.now.Add(time.Second))
	if err != nil {
		t.Fatalf("IssueGrant() error = %v", err)
	}
	verifier, err := NewEd25519Verifier(kernelSigner.PublicKeyBytes(), fixture.issuerConfig().SigningKeyRef, fixture.issuerConfig().KernelTrustRootID)
	if err != nil {
		t.Fatalf("NewEd25519Verifier() error = %v", err)
	}
	signedGrant.Grant.GeneratedSpecHash = hash("9")
	if err := verifier.VerifyGrant(signedGrant, fixture.now.Add(time.Second)); !errors.Is(err, ErrSignatureRejected) {
		t.Fatalf("VerifyGrant(tampered) error = %v, want signature rejected", err)
	}
}

func TestIssueGrantRejectsModifiedVerifierResult(t *testing.T) {
	fixture := newApprovalFixture(t)
	verified, err := VerifyGeneratedSpecQuorum(fixture.challenge, []contracts.GeneratedSpecApprovalAssertion{fixture.assertion}, fixture.store, fixture.options, fixture.now)
	if err != nil {
		t.Fatalf("VerifyGeneratedSpecQuorum() error = %v", err)
	}
	verified.ApprovalID = "approval-substituted"
	kernelSigner, err := crypto.NewEd25519Signer("generated-spec-kernel")
	if err != nil {
		t.Fatalf("NewEd25519Signer() error = %v", err)
	}
	if _, err := IssueGrant(fixture.challenge, verified, "grant-a", fixture.nonce("b"), kernelSigner, fixture.issuerConfig(), fixture.now.Add(time.Second)); err == nil {
		t.Fatal("IssueGrant() accepted a modified verifier result")
	}
}

type approvalFixture struct {
	challenge contracts.GeneratedSpecApprovalChallenge
	assertion contracts.GeneratedSpecApprovalAssertion
	store     approvalverify.TrustStore
	options   VerifyOptions
	now       time.Time
}

func newApprovalFixture(t *testing.T) approvalFixture {
	t.Helper()
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	challenge, err := (contracts.GeneratedSpecApprovalChallenge{
		Domain: contracts.GeneratedSpecApprovalChallengeDomainV1, SchemaVersion: contracts.GeneratedSpecApprovalChallengeSchemaV1,
		ContractVersion: contracts.GeneratedSpecApprovalChallengeContractV1,
		ChallengeID:     "challenge-a", ApprovalID: "approval-a", TenantID: "tenant-a", WorkspaceID: "workspace-a",
		Audience: contracts.GeneratedSpecApprovalAudienceV1, GeneratedSpecID: "spec-a", GeneratedSpecHash: hash("a"),
		ExecutionPlanHash: hash("b"), PlanTransactionHash: hash("c"), WriteSetHash: hash("d"),
		VerificationScopeHash: hash("e"), PolicyEnvelopeHash: hash("f"), PolicyVersion: "policy-v1", PolicyEpoch: "epoch-1",
		Action: contracts.GeneratedSpecApprovalActionV1, RequestingPrincipalID: "user:requester-a",
		AuthoritySource: "authority-a", AuthorityVersion: "version-a", AuthoritySnapshotHash: hash("0"),
		RequiredRole: "generated-spec-approver", Quorum: 1, ServerIdentity: "spiffe://helm/kernel-a",
		HoldStartedAt: now.Add(-time.Minute), EligibleAt: now.Add(-time.Second), IssuedAt: now,
		ExpiresAt: now.Add(5 * time.Minute), Nonce: stringsRepeat("1", 64),
	}).Seal()
	if err != nil {
		t.Fatalf("challenge Seal() error = %v", err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	assertion := contracts.GeneratedSpecApprovalAssertion{
		Domain: contracts.GeneratedSpecApprovalAssertionDomainV1, SchemaVersion: contracts.GeneratedSpecApprovalAssertionSchemaV1,
		ContractVersion: contracts.GeneratedSpecApprovalAssertionContractV1, ChallengeID: challenge.ChallengeID,
		ChallengeHash: challenge.ChallengeHash, KeyID: "approver-key-a", Algorithm: contracts.GeneratedSpecApprovalAssertionEd25519,
	}
	digest, err := assertion.SigningDigest()
	if err != nil {
		t.Fatalf("SigningDigest() error = %v", err)
	}
	assertion.Signature = "ed25519:" + hex.EncodeToString(ed25519.Sign(private, digest))
	store := approvalverify.TrustStore{
		AuthoritySource: challenge.AuthoritySource, AuthorityVersion: challenge.AuthorityVersion,
		AuthoritySnapshotHash: challenge.AuthoritySnapshotHash,
		Keys: map[string]approvalverify.TrustedApproverKey{
			assertion.KeyID: {
				KeyID: assertion.KeyID, TenantID: challenge.TenantID, PrincipalID: "user:approver-a",
				CredentialID: "credential-a", DeviceID: "device-a", PublicKey: public,
				WorkspaceIDs: []string{challenge.WorkspaceID}, Roles: []string{challenge.RequiredRole},
				Actions: []string{challenge.Action}, Audiences: []string{challenge.Audience}, Enabled: true,
				NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			},
		},
	}
	return approvalFixture{challenge: challenge, assertion: assertion, store: store, now: now,
		options: VerifyOptions{Expected: expectedFor(challenge), MinHoldDuration: time.Second, MaxChallengeTTL: 10 * time.Minute, MaxAssertions: 2}}
}

func (f approvalFixture) issuerConfig() IssuerConfig {
	return IssuerConfig{GrantTTL: time.Minute, ServerIdentity: f.challenge.ServerIdentity, KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/generated-spec-a"}
}

func (f approvalFixture) nonce(character string) string { return stringsRepeat(character, 64) }

func expectedFor(challenge contracts.GeneratedSpecApprovalChallenge) ExpectedBinding {
	return ExpectedBinding{
		ChallengeID: challenge.ChallengeID, ChallengeHash: challenge.ChallengeHash, ApprovalID: challenge.ApprovalID,
		TenantID: challenge.TenantID, WorkspaceID: challenge.WorkspaceID, Audience: challenge.Audience,
		GeneratedSpecID: challenge.GeneratedSpecID, GeneratedSpecHash: challenge.GeneratedSpecHash,
		ExecutionPlanHash: challenge.ExecutionPlanHash, PlanTransactionHash: challenge.PlanTransactionHash,
		WriteSetHash: challenge.WriteSetHash, VerificationScopeHash: challenge.VerificationScopeHash,
		PolicyEnvelopeHash: challenge.PolicyEnvelopeHash, PolicyVersion: challenge.PolicyVersion,
		PolicyEpoch: challenge.PolicyEpoch, Action: challenge.Action, RequestingPrincipalID: challenge.RequestingPrincipalID,
		AuthoritySource: challenge.AuthoritySource, AuthorityVersion: challenge.AuthorityVersion,
		AuthoritySnapshotHash: challenge.AuthoritySnapshotHash, RequiredRole: challenge.RequiredRole,
		Quorum: challenge.Quorum, ServerIdentity: challenge.ServerIdentity,
	}
}

func hash(character string) string { return "sha256:" + stringsRepeat(character, 64) }
func stringsRepeat(character string, count int) string {
	bytes := make([]byte, count)
	for index := range bytes {
		bytes[index] = character[0]
	}
	return string(bytes)
}
