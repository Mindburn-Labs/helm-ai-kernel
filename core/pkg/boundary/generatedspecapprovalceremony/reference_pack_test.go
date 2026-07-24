package generatedspecapprovalceremony

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/generatedspecapproval"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type generatedSpecCeremonyVectorFile struct {
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type generatedSpecCeremonySignedVector struct {
	generatedSpecCeremonyVectorFile
	SigningPayload generatedSpecCeremonyVectorFile `json:"signing_payload"`
	PublicKey      string                          `json:"public_key"`
	Signature      string                          `json:"signature"`
}

type generatedSpecCeremonyNegativeVector struct {
	ID            string `json:"id"`
	Mutation      string `json:"mutation"`
	ExpectedError string `json:"expected_error"`
}

type generatedSpecCeremonyVectorIndex struct {
	Comment          string                                `json:"$comment"`
	SchemaVersion    string                                `json:"schema_version"`
	ContractVersion  string                                `json:"contract_version"`
	QuantumPosture   string                                `json:"quantum_posture"`
	VerificationTime string                                `json:"verification_time"`
	Challenge        generatedSpecCeremonyVectorFile       `json:"challenge"`
	Grant            generatedSpecCeremonySignedVector     `json:"grant"`
	Consumption      generatedSpecCeremonySignedVector     `json:"consumption"`
	Lifecycle        generatedSpecCeremonyVectorFile       `json:"lifecycle"`
	NegativeVectors  []generatedSpecCeremonyNegativeVector `json:"negative_vectors"`
}

type generatedSpecCeremonyLifecycleVector struct {
	ApprovalID                 string  `json:"approval_id"`
	States                     []State `json:"states"`
	FirstConsumeVersion        int64   `json:"first_consume_version"`
	ReplayExpectedError        string  `json:"replay_expected_error"`
	RecoveryMatchesConsumption bool    `json:"recovery_matches_consumption"`
}

func TestGeneratedSpecApprovalCeremonyReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildGeneratedSpecApprovalCeremonyReferencePack(t)
	root := filepath.Join("..", "..", "..", "..", "reference_packs", "generated-spec-approval-ceremony-v1")
	if os.Getenv("UPDATE_GENERATED_SPEC_APPROVAL_CEREMONY_VECTORS") == "1" {
		if err := os.MkdirAll(root, 0o755); err != nil {
			t.Fatalf("create generated spec ceremony reference pack: %v", err)
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(root, name), content, 0o644); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
		}
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s differs from source-owned Go fixture; run UPDATE_GENERATED_SPEC_APPROVAL_CEREMONY_VECTORS=1 go test ./pkg/boundary/generatedspecapprovalceremony -run TestGeneratedSpecApprovalCeremonyReferencePackMatchesGoImplementation", name)
		}
	}
}

func buildGeneratedSpecApprovalCeremonyReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	fixture := newGeneratedSpecCeremonyReferencePackFixture(t)
	ctx := context.Background()

	hold, err := fixture.service.BeginHold(ctx, fixture.binding.BindingRef)
	if err != nil {
		t.Fatalf("BeginHold() error = %v", err)
	}
	fixture.advance(fixture.config.MinHoldDuration)
	challenged, err := fixture.service.IssueChallenge(ctx, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueChallenge() error = %v", err)
	}
	assertion := fixture.assertion(t, *challenged.Challenge)
	quorum, err := fixture.service.VerifyQuorum(ctx, hold.ApprovalID, []contracts.GeneratedSpecApprovalAssertion{assertion})
	if err != nil {
		t.Fatalf("VerifyQuorum() error = %v", err)
	}
	granted, err := fixture.service.IssueGrant(ctx, hold.ApprovalID)
	if err != nil {
		t.Fatalf("IssueGrant() error = %v", err)
	}
	fixture.advance(time.Second)
	consumed, err := fixture.service.ConsumeGrant(ctx, hold.ApprovalID, granted.SignedGrant.Grant.GrantID, granted.SignedGrant.Grant.GrantHash, granted.SignedGrant.Grant.Nonce)
	if err != nil {
		t.Fatalf("ConsumeGrant() error = %v", err)
	}
	if _, err := fixture.service.ConsumeGrant(ctx, hold.ApprovalID, granted.SignedGrant.Grant.GrantID, granted.SignedGrant.Grant.GrantHash, granted.SignedGrant.Grant.Nonce); !errors.Is(err, ErrTransitionConflict) {
		t.Fatalf("ConsumeGrant(replay) error = %v, want transition conflict", err)
	}
	recovered, err := fixture.service.RecoverGrantConsumption(ctx, hold.ApprovalID, granted.SignedGrant.Grant.GrantID, granted.SignedGrant.Grant.GrantHash, granted.SignedGrant.Grant.Nonce)
	if err != nil {
		t.Fatalf("RecoverGrantConsumption() error = %v", err)
	}

	challengeJSON := generatedSpecCeremonyCanonicalJSON(t, *challenged.Challenge)
	grantJSON := generatedSpecCeremonyCanonicalJSON(t, granted.SignedGrant.Grant)
	consumptionJSON := generatedSpecCeremonyCanonicalJSON(t, consumed.SignedConsumption.Consumption)
	lifecycleJSON := generatedSpecCeremonyCanonicalJSON(t, generatedSpecCeremonyLifecycleVector{
		ApprovalID:                 hold.ApprovalID,
		States:                     []State{hold.State, challenged.State, quorum.State, granted.State, consumed.State},
		FirstConsumeVersion:        consumed.Version,
		ReplayExpectedError:        "transition_conflict",
		RecoveryMatchesConsumption: recovered.SignedConsumption.Consumption.ConsumptionHash == consumed.SignedConsumption.Consumption.ConsumptionHash,
	})
	grantPayload, err := generatedspecapproval.GrantSigningPayload(granted.SignedGrant.Grant, granted.SignedGrant.Algorithm)
	if err != nil {
		t.Fatalf("GrantSigningPayload() error = %v", err)
	}
	consumptionPayload, err := generatedspecapproval.ConsumptionSigningPayload(consumed.SignedConsumption.Consumption, consumed.SignedConsumption.Algorithm)
	if err != nil {
		t.Fatalf("ConsumptionSigningPayload() error = %v", err)
	}

	index := generatedSpecCeremonyVectorIndex{
		Comment:          "Deterministic source-contract/parity vectors for the GeneratedSpec approval ceremony foundation. They do not prove durable persistence, runtime transport, Control Plane approval, or production authority. quantum_posture: classical Ed25519 only; no hybrid or post-quantum claim.",
		SchemaVersion:    "generated-spec-approval-ceremony-vectors.v1",
		ContractVersion:  challenged.Challenge.ContractVersion,
		QuantumPosture:   "classical_ed25519_only",
		VerificationTime: consumed.SignedConsumption.Consumption.ConsumedAt.Format(time.RFC3339Nano),
		Challenge: generatedSpecCeremonyVectorFile{
			Canonical: "challenge.c14n.json", SHA256: generatedSpecCeremonyVectorHash(challengeJSON),
		},
		Grant: generatedSpecCeremonySignedVector{
			generatedSpecCeremonyVectorFile: generatedSpecCeremonyVectorFile{Canonical: "grant.c14n.json", SHA256: generatedSpecCeremonyVectorHash(grantJSON)},
			SigningPayload:                  generatedSpecCeremonyVectorFile{Canonical: "grant_signing_payload.c14n.json", SHA256: generatedSpecCeremonyVectorHash(grantPayload)},
			PublicKey:                       "ed25519:" + fixture.signer.PublicKey(),
			Signature:                       "ed25519:" + granted.SignedGrant.Signature,
		},
		Consumption: generatedSpecCeremonySignedVector{
			generatedSpecCeremonyVectorFile: generatedSpecCeremonyVectorFile{Canonical: "consumption.c14n.json", SHA256: generatedSpecCeremonyVectorHash(consumptionJSON)},
			SigningPayload:                  generatedSpecCeremonyVectorFile{Canonical: "consumption_signing_payload.c14n.json", SHA256: generatedSpecCeremonyVectorHash(consumptionPayload)},
			PublicKey:                       "ed25519:" + fixture.signer.PublicKey(),
			Signature:                       "ed25519:" + consumed.SignedConsumption.Signature,
		},
		Lifecycle: generatedSpecCeremonyVectorFile{
			Canonical: "lifecycle.c14n.json", SHA256: generatedSpecCeremonyVectorHash(lifecycleJSON),
		},
		NegativeVectors: []generatedSpecCeremonyNegativeVector{
			{ID: "challenge_binding_tamper", Mutation: "set_challenge_policy_epoch_to_tampered", ExpectedError: "challenge_hash_mismatch"},
			{ID: "grant_binding_tamper", Mutation: "set_grant_generated_spec_hash_to_tampered", ExpectedError: "grant_hash_mismatch"},
			{ID: "consumption_grant_substitution", Mutation: "set_consumption_grant_id_to_grant_b_and_reseal", ExpectedError: "consumption_binding_rejected"},
			{ID: "expiry_boundary", Mutation: "set_verification_time_to_grant_expiry", ExpectedError: "inactive_grant"},
			{ID: "grant_signature_tamper", Mutation: "flip_grant_signature_last_bit", ExpectedError: "signature_rejected"},
			{ID: "single_use_replay", Mutation: "replay_second_consume", ExpectedError: "transition_conflict"},
			{ID: "quorum_not_verified", Mutation: "set_challenge_quorum_above_approvers_and_reseal", ExpectedError: "quorum_not_verified"},
			{ID: "duplicate_approver", Mutation: "duplicate_grant_approver_and_reseal", ExpectedError: "contract_mismatch"},
		},
	}
	indexJSON, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatalf("marshal generated spec ceremony vectors: %v", err)
	}
	return map[string][]byte{
		"challenge.c14n.json":                   append(challengeJSON, '\n'),
		"grant.c14n.json":                       append(grantJSON, '\n'),
		"consumption.c14n.json":                 append(consumptionJSON, '\n'),
		"grant_signing_payload.c14n.json":       append(grantPayload, '\n'),
		"consumption_signing_payload.c14n.json": append(consumptionPayload, '\n'),
		"lifecycle.c14n.json":                   append(lifecycleJSON, '\n'),
		"vectors.json":                          append(indexJSON, '\n'),
	}
}

func generatedSpecCeremonyCanonicalJSON(t *testing.T, value any) []byte {
	t.Helper()
	canonical, err := canonicalize.JCS(value)
	if err != nil {
		t.Fatalf("canonicalize generated spec ceremony reference value: %v", err)
	}
	return canonical
}

func generatedSpecCeremonyVectorHash(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type generatedSpecCeremonyReferencePackFixture struct {
	now        time.Time
	config     ServiceConfig
	binding    Binding
	service    *Service
	privateKey ed25519.PrivateKey
	keyID      string
	signer     *crypto.Ed25519Signer
}

func newGeneratedSpecCeremonyReferencePackFixture(t *testing.T) *generatedSpecCeremonyReferencePackFixture {
	t.Helper()
	fixture := &generatedSpecCeremonyReferencePackFixture{
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
		keyID: "approver-key-a",
	}
	fixture.privateKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	fixture.signer = crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize)), "generated-spec-ceremony-vector")
	verifier, err := generatedspecapproval.NewEd25519Verifier(fixture.signer.PublicKeyBytes(), fixture.config.SigningKeyRef, fixture.config.KernelTrustRootID)
	if err != nil {
		t.Fatalf("NewEd25519Verifier() error = %v", err)
	}
	authority := &authorityStub{store: approvalverify.TrustStore{
		AuthoritySource: fixture.binding.AuthoritySource, AuthorityVersion: fixture.binding.AuthorityVersion, AuthoritySnapshotHash: fixture.binding.AuthoritySnapshotHash,
		Keys: map[string]approvalverify.TrustedApproverKey{
			fixture.keyID: {
				KeyID: fixture.keyID, TenantID: fixture.binding.TenantID, PrincipalID: "user:approver-a", CredentialID: "credential-a", DeviceID: "device-a",
				PublicKey: fixture.privateKey.Public().(ed25519.PublicKey), WorkspaceIDs: []string{fixture.binding.WorkspaceID}, Roles: []string{fixture.binding.RequiredRole},
				Actions: []string{fixture.binding.Action}, Audiences: []string{fixture.binding.Audience}, Enabled: true,
				NotBefore: fixture.now.Add(-time.Hour), NotAfter: fixture.now.Add(time.Hour),
			},
		},
	}}
	service, err := newService(
		newMemoryStore(8*time.Minute), bindingStub{binding: fixture.binding}, authority,
		&controlStub{identity: ControlIdentity{Subject: "spiffe://helm/control-api", TenantID: fixture.binding.TenantID, WorkspaceID: fixture.binding.WorkspaceID}},
		&consumerStub{identity: ConsumerIdentity{Subject: "spiffe://helm/control-plane-a", TenantID: fixture.binding.TenantID, WorkspaceID: fixture.binding.WorkspaceID, Audience: fixture.binding.Audience}},
		fixture.signer, verifier, func() time.Time { return fixture.now }, bytes.NewReader(bytes.Repeat([]byte{0x42}, 256)), fixture.config,
	)
	if err != nil {
		t.Fatalf("newService() error = %v", err)
	}
	fixture.service = service
	return fixture
}

func (f *generatedSpecCeremonyReferencePackFixture) advance(duration time.Duration) {
	f.now = f.now.Add(duration)
}

func (f *generatedSpecCeremonyReferencePackFixture) assertion(t *testing.T, challenge contracts.GeneratedSpecApprovalChallenge) contracts.GeneratedSpecApprovalAssertion {
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
