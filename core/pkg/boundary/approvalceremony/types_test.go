package approvalceremony

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/approvalverify"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
)

func TestRecordValidatesCompleteLifecycle(t *testing.T) {
	hold, challenge, verified, grant := ceremonyFixtures(t)
	cases := []Record{
		hold,
		withChallenge(hold, challenge),
		withVerified(withChallenge(hold, challenge), verified),
		withGrant(withVerified(withChallenge(hold, challenge), verified), grant),
	}
	consumed := cases[len(cases)-1]
	consumed.State = StateConsumed
	consumed.UpdatedAt = grant.IssuedAt.Add(time.Minute)
	consumedAt := consumed.UpdatedAt
	consumed.ConsumedAt = &consumedAt
	consumed.ConsumedBy = "spiffe://helm/data-plane-a"
	consumption := consumptionForGrant(t, grant, consumed.ConsumedBy, consumedAt)
	consumed.GrantConsumption = &consumption
	consumed.ConsumptionSignatureAlgorithm = GrantSignatureEd25519
	consumed.ConsumptionSignature = strings.Repeat("c", 128)
	consumed.Version++
	cases = append(cases, consumed)

	for _, record := range cases {
		t.Run(string(record.State), func(t *testing.T) {
			if err := record.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestRecordRejectsAuthoritySubstitution(t *testing.T) {
	hold, challenge, verified, grant := ceremonyFixtures(t)
	tests := map[string]func(*Record){
		"binding reference": func(record *Record) {
			record.Spec.BindingRef = "decision://helm/policy/substituted"
		},
		"challenge tenant": func(record *Record) {
			mutated := *record.Challenge
			mutated.TenantID = "tenant-b"
			mutated.ConnectorAuthority.TenantID = "tenant-b"
			mutated.ConnectorAuthority.AuthorityHash = ""
			var err error
			mutated.ConnectorAuthority, err = mutated.ConnectorAuthority.Seal()
			if err != nil {
				t.Fatal(err)
			}
			mutated.ChallengeHash = ""
			sealed, err := mutated.Seal()
			if err != nil {
				t.Fatal(err)
			}
			record.Challenge = &sealed
		},
		"verified effect": func(record *Record) { record.VerifiedRef.EffectHash = shaRef("9") },
		"grant signer set": func(record *Record) {
			mutated := *record.Grant
			mutated.SignerSetHash = shaRef("8")
			mutated.GrantHash = ""
			sealed, err := mutated.Seal()
			if err != nil {
				t.Fatal(err)
			}
			record.Grant = &sealed
		},
		"grant signature": func(record *Record) { record.GrantSignature = "00" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := withGrant(withVerified(withChallenge(hold, challenge), verified), grant)
			mutate(&record)
			if err := record.Validate(); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("Validate() error = %v, want ErrInvalidRecord", err)
			}
		})
	}
}

func TestRecordRejectsStateArtifactDrift(t *testing.T) {
	hold, challenge, verified, grant := ceremonyFixtures(t)
	tests := []Record{
		withChallenge(hold, challenge),
		withVerified(withChallenge(hold, challenge), verified),
		withGrant(withVerified(withChallenge(hold, challenge), verified), grant),
	}
	tests[0].State = StateHoldPending
	tests[1].State = StateChallengeIssued
	tests[2].State = StateQuorumVerified
	for _, record := range tests {
		if err := record.Validate(); !errors.Is(err, ErrInvalidRecord) {
			t.Fatalf("state %s drift error = %v, want ErrInvalidRecord", record.State, err)
		}
	}
}

func TestRecordRejectsMutableExpiryAndLateConsumption(t *testing.T) {
	hold, challenge, verified, grant := ceremonyFixtures(t)
	granted := withGrant(withVerified(withChallenge(hold, challenge), verified), grant)

	shadowExtended := granted
	extended := grant.ExpiresAt.Add(time.Hour)
	shadowExtended.ExpiresAt = &extended
	if err := shadowExtended.Validate(); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("extended expiry shadow error = %v, want ErrInvalidRecord", err)
	}

	lateConsumption := granted
	lateConsumption.State = StateConsumed
	lateConsumption.UpdatedAt = grant.ExpiresAt
	consumedAt := grant.ExpiresAt
	lateConsumption.ConsumedAt = &consumedAt
	lateConsumption.ConsumedBy = "spiffe://helm/data-plane-a"
	consumption := consumptionForGrant(t, grant, lateConsumption.ConsumedBy, grant.ExpiresAt.Add(-time.Second))
	consumption.ConsumedAt = consumedAt
	lateConsumption.GrantConsumption = &consumption
	lateConsumption.ConsumptionSignatureAlgorithm = GrantSignatureEd25519
	lateConsumption.ConsumptionSignature = strings.Repeat("c", 128)
	lateConsumption.Version++
	if err := lateConsumption.Validate(); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("late consumption error = %v, want ErrInvalidRecord", err)
	}

	earlyExpiry := withChallenge(hold, challenge)
	earlyExpiry.State = StateExpired
	earlyExpiry.UpdatedAt = challenge.ExpiresAt.Add(-time.Second)
	earlyExpiry.Version++
	if err := earlyExpiry.Validate(); !errors.Is(err, ErrInvalidRecord) {
		t.Fatalf("early expiry transition error = %v, want ErrInvalidRecord", err)
	}
}

func ceremonyFixtures(t *testing.T) (Record, contracts.ApprovalChallenge, approvalverify.VerifiedApprovalRef, contracts.ApprovalGrant) {
	t.Helper()
	holdStarted := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	hold := Record{
		ApprovalID: "approval-a", TenantID: "tenant-a", WorkspaceID: "workspace-a",
		State: StateHoldPending, HoldStartedAt: holdStarted,
		CreatedAt: holdStarted, UpdatedAt: holdStarted, Version: 1,
	}
	challenge, err := (contracts.ApprovalChallenge{
		Domain: contracts.ApprovalChallengeDomainV1, SchemaVersion: contracts.ApprovalChallengeSchemaV1,
		ContractVersion: contracts.ApprovalChallengeContractV1,
		ChallengeID:     "challenge-a", ApprovalID: hold.ApprovalID, TenantID: hold.TenantID,
		WorkspaceID: hold.WorkspaceID, Audience: "packs.lifecycle", PackID: "pack-a",
		PackVersion: "1.0.0", PackManifestHash: shaRef("a"), Action: contracts.ApprovalGrantActionInstall,
		ConnectorAuthority: connectorAuthorityFixture(t),
		IntentHash:         shaRef("0"), EffectHash: shaRef("1"), PlanHash: shaRef("2"),
		Decision: contracts.ApprovalGrantDecisionAllow, PolicyVersion: "policy-v1",
		PolicyEpoch: "epoch-1", PolicyHash: shaRef("3"),
		AuthoritySource: "spiffe://helm/authority/approvers", AuthorityVersion: "authority-v1",
		AuthoritySnapshotHash: shaRef("4"), RequiredRole: "pack-admin", Quorum: 2,
		ServerIdentity: "spiffe://helm/kernel-a", HoldStartedAt: holdStarted,
		EligibleAt: holdStarted.Add(5 * time.Minute), IssuedAt: holdStarted.Add(6 * time.Minute),
		ExpiresAt: holdStarted.Add(15 * time.Minute), Nonce: strings.Repeat("5", 64),
	}).Seal()
	if err != nil {
		t.Fatalf("seal challenge: %v", err)
	}
	hold.Spec = specFromChallenge(challenge)
	verifiedAt := challenge.IssuedAt.Add(time.Minute)
	verified := approvalverify.VerifiedApprovalRef{
		ApprovalID: challenge.ApprovalID, ChallengeID: challenge.ChallengeID,
		ChallengeHash: challenge.ChallengeHash, TenantID: challenge.TenantID,
		WorkspaceID: challenge.WorkspaceID, Audience: challenge.Audience,
		PackID: challenge.PackID, PackVersion: challenge.PackVersion,
		PackManifestHash: challenge.PackManifestHash, Action: challenge.Action,
		ConnectorAuthority: challenge.ConnectorAuthority,
		IntentHash:         challenge.IntentHash, EffectHash: challenge.EffectHash,
		PlanHash: challenge.PlanHash, Decision: challenge.Decision,
		PolicyVersion: challenge.PolicyVersion, PolicyEpoch: challenge.PolicyEpoch,
		PolicyHash: challenge.PolicyHash, AuthoritySource: challenge.AuthoritySource,
		AuthorityVersion: challenge.AuthorityVersion, AuthoritySnapshotHash: challenge.AuthoritySnapshotHash,
		ServerIdentity: challenge.ServerIdentity, RequiredRole: challenge.RequiredRole,
		Quorum: challenge.Quorum, SignerSetHash: shaRef("6"), VerifiedAt: verifiedAt,
		Signers: []approvalverify.VerifiedSigner{
			{PrincipalID: "principal-a", CredentialID: "credential-a", DeviceID: "device-a", KeyID: "key-a", Role: challenge.RequiredRole, AssertionHash: shaRef("7")},
			{PrincipalID: "principal-b", CredentialID: "credential-b", DeviceID: "device-b", KeyID: "key-b", Role: challenge.RequiredRole, AssertionHash: shaRef("8")},
		},
	}
	ceremonyHash, err := CeremonyCommitment(withVerified(withChallenge(hold, challenge), verified))
	if err != nil {
		t.Fatalf("commit ceremony: %v", err)
	}
	grant, err := (contracts.ApprovalGrant{
		SchemaVersion: contracts.ApprovalGrantSchemaV1, ContractVersion: contracts.ApprovalGrantContractV1,
		GrantID: "grant-a", TenantID: verified.TenantID, WorkspaceID: verified.WorkspaceID,
		Audience: verified.Audience, PackID: verified.PackID, PackVersion: verified.PackVersion,
		PackManifestHash: verified.PackManifestHash, Action: verified.Action,
		ConnectorAuthority: verified.ConnectorAuthority,
		IntentHash:         verified.IntentHash, EffectHash: verified.EffectHash, PlanHash: verified.PlanHash,
		Decision: verified.Decision, PolicyVersion: verified.PolicyVersion,
		PolicyEpoch: verified.PolicyEpoch, PolicyHash: verified.PolicyHash,
		ApprovalID: verified.ApprovalID, CeremonyHash: ceremonyHash, SignerSetHash: verified.SignerSetHash,
		ServerIdentity: verified.ServerIdentity, KernelTrustRootID: "kernel-root-a",
		SigningKeyRef: "kms://helm/approval-a", IssuedAt: verifiedAt.Add(time.Minute),
		ExpiresAt: challenge.ExpiresAt, Nonce: strings.Repeat("a", 64),
	}).Seal()
	if err != nil {
		t.Fatalf("seal grant: %v", err)
	}
	return hold, challenge, verified, grant
}

func specFromChallenge(challenge contracts.ApprovalChallenge) ChallengeSpec {
	return ChallengeSpec{
		BindingRef: "decision://helm/policy/approval-a",
		TenantID:   challenge.TenantID, WorkspaceID: challenge.WorkspaceID, Audience: challenge.Audience,
		PackID: challenge.PackID, PackVersion: challenge.PackVersion, PackManifestHash: challenge.PackManifestHash,
		Action: challenge.Action, ConnectorAuthority: challenge.ConnectorAuthority,
		IntentHash: challenge.IntentHash, EffectHash: challenge.EffectHash,
		PlanHash: challenge.PlanHash, Decision: challenge.Decision, PolicyVersion: challenge.PolicyVersion,
		PolicyEpoch: challenge.PolicyEpoch, PolicyHash: challenge.PolicyHash,
		AuthoritySource: challenge.AuthoritySource, AuthorityVersion: challenge.AuthorityVersion,
		AuthoritySnapshotHash: challenge.AuthoritySnapshotHash, RequiredRole: challenge.RequiredRole,
		Quorum: challenge.Quorum, ServerIdentity: challenge.ServerIdentity,
	}
}

func withChallenge(record Record, challenge contracts.ApprovalChallenge) Record {
	record.State = StateChallengeIssued
	record.Challenge = &challenge
	expiresAt := challenge.ExpiresAt
	record.ExpiresAt = &expiresAt
	record.UpdatedAt = challenge.IssuedAt
	record.Version++
	return record
}

func withVerified(record Record, verified approvalverify.VerifiedApprovalRef) Record {
	record.State = StateQuorumVerified
	record.VerifiedRef = &verified
	record.UpdatedAt = verified.VerifiedAt
	record.Version++
	return record
}

func withGrant(record Record, grant contracts.ApprovalGrant) Record {
	record.State = StateGrantIssued
	record.Grant = &grant
	expiresAt := grant.ExpiresAt
	record.ExpiresAt = &expiresAt
	record.GrantSignatureAlgorithm = GrantSignatureEd25519
	record.GrantSignature = strings.Repeat("b", 128)
	record.UpdatedAt = grant.IssuedAt
	record.Version++
	return record
}

func consumptionForGrant(t *testing.T, grant contracts.ApprovalGrant, consumedBy string, consumedAt time.Time) contracts.ApprovalGrantConsumption {
	t.Helper()
	consumption, err := (contracts.ApprovalGrantConsumption{
		SchemaVersion: contracts.ApprovalGrantConsumptionSchemaV1, ContractVersion: contracts.ApprovalGrantConsumptionContractV1,
		ApprovalID: grant.ApprovalID, GrantID: grant.GrantID, GrantHash: grant.GrantHash,
		TenantID: grant.TenantID, WorkspaceID: grant.WorkspaceID, Audience: grant.Audience, ConsumedBy: consumedBy,
		PackID: grant.PackID, PackVersion: grant.PackVersion, PackManifestHash: grant.PackManifestHash, Action: grant.Action,
		ConnectorAuthority: grant.ConnectorAuthority,
		IntentHash:         grant.IntentHash, EffectHash: grant.EffectHash, PlanHash: grant.PlanHash,
		PolicyVersion: grant.PolicyVersion, PolicyEpoch: grant.PolicyEpoch, PolicyHash: grant.PolicyHash,
		ServerIdentity: grant.ServerIdentity, KernelTrustRootID: grant.KernelTrustRootID, SigningKeyRef: grant.SigningKeyRef,
		GrantIssuedAt: grant.IssuedAt, GrantExpiresAt: grant.ExpiresAt, ConsumedAt: consumedAt,
	}).Seal()
	if err != nil {
		t.Fatalf("seal consumption: %v", err)
	}
	return consumption
}

func shaRef(char string) string {
	return "sha256:" + strings.Repeat(char, 64)
}

func connectorAuthorityFixture(t *testing.T) contracts.ApprovalConnectorAuthority {
	t.Helper()
	authority, err := (contracts.ApprovalConnectorAuthority{
		SchemaVersion:   contracts.ApprovalConnectorAuthoritySchemaV1,
		ContractVersion: contracts.ApprovalConnectorAuthorityContractV1,
		State:           contracts.ApprovalConnectorAuthorityStateV1,
		BindingRef:      "decision://helm/policy/approval-a", TenantID: "tenant-a", WorkspaceID: "workspace-a",
		PackID: "pack-a", PackVersion: "1.0.0", PackManifestHash: shaRef("a"),
		Action: contracts.ApprovalGrantActionInstall, ConnectorAction: contracts.ApprovalGrantActionInstall,
		EffectHash: shaRef("1"), PolicyHash: shaRef("3"),
		ConnectorID: "connector-a", ConnectorVersion: "1.0.0",
		ReleaseScopeKind: contracts.ConnectorReleaseAuthorityScopeGlobal, ReleaseAuthorityID: "connector-registry-a",
		ReleaseRegistryRevision: 1, ReleaseAuthorityHash: shaRef("4"), ConnectorExecutorKind: "digital",
		ConnectorBinaryHash: shaRef("9"), ConnectorSignatureRef: "sigstore://connector-a/1.0.0",
		ConnectorSignatureHash: shaRef("6"),
		ConnectorSignerID:      "publisher-a", ConnectorSandboxProfile: "sandbox-pack-lifecycle-v1",
		ConnectorDriftPolicyRef: "policy://connector-drift/v1", CertificationRef: "cert://connector-a/1.0.0",
		CertificationHash: shaRef("b"), CertificationAuthority: "spiffe://helm/certification-authority",
	}).Seal()
	if err != nil {
		t.Fatalf("seal connector authority: %v", err)
	}
	return authority
}
