package contracts

import (
	"errors"
	"testing"
	"time"
)

func TestGeneratedSpecApprovalChallengeSealsEveryAuthorityBearingField(t *testing.T) {
	base := validGeneratedSpecApprovalChallenge()
	sealed, err := base.Seal()
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}

	mutations := map[string]func(*GeneratedSpecApprovalChallenge){
		"tenant":              func(c *GeneratedSpecApprovalChallenge) { c.TenantID = "tenant-b" },
		"workspace":           func(c *GeneratedSpecApprovalChallenge) { c.WorkspaceID = "workspace-b" },
		"generated spec":      func(c *GeneratedSpecApprovalChallenge) { c.GeneratedSpecID = "spec-b" },
		"generated spec hash": func(c *GeneratedSpecApprovalChallenge) { c.GeneratedSpecHash = sha256Ref("b") },
		"execution plan":      func(c *GeneratedSpecApprovalChallenge) { c.ExecutionPlanHash = sha256Ref("c") },
		"plan transaction":    func(c *GeneratedSpecApprovalChallenge) { c.PlanTransactionHash = sha256Ref("d") },
		"write set":           func(c *GeneratedSpecApprovalChallenge) { c.WriteSetHash = sha256Ref("e") },
		"verification scope":  func(c *GeneratedSpecApprovalChallenge) { c.VerificationScopeHash = sha256Ref("f") },
		"policy":              func(c *GeneratedSpecApprovalChallenge) { c.PolicyEnvelopeHash = sha256Ref("0") },
		"requester":           func(c *GeneratedSpecApprovalChallenge) { c.RequestingPrincipalID = "user:requester-b" },
		"authority snapshot":  func(c *GeneratedSpecApprovalChallenge) { c.AuthoritySnapshotHash = sha256Ref("1") },
		"nonce":               func(c *GeneratedSpecApprovalChallenge) { c.Nonce = repeatHex("2") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			changed, err := candidate.Seal()
			if err != nil {
				t.Fatalf("Seal() error = %v", err)
			}
			if changed.ChallengeHash == sealed.ChallengeHash {
				t.Fatal("authority mutation did not change challenge hash")
			}
		})
	}
}

func TestGeneratedSpecApprovalChallengeChecksWindowAndHashIntegrity(t *testing.T) {
	challenge, err := validGeneratedSpecApprovalChallenge().Seal()
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if err := challenge.ValidateAt(challenge.IssuedAt); err != nil {
		t.Fatalf("ValidateAt(issued) error = %v", err)
	}
	if err := challenge.ValidateAt(challenge.ExpiresAt); !errors.Is(err, ErrGeneratedSpecApprovalChallengeInactive) {
		t.Fatalf("ValidateAt(expired) error = %v, want inactive", err)
	}
	challenge.GeneratedSpecHash = sha256Ref("b")
	if err := challenge.ValidateAt(challenge.IssuedAt); !errors.Is(err, ErrGeneratedSpecApprovalChallengeIntegrity) {
		t.Fatalf("ValidateAt(tampered) error = %v, want integrity", err)
	}
}

func TestGeneratedSpecApprovalGrantRejectsSelfApprovalAndUnorderedApprovers(t *testing.T) {
	grant := validGeneratedSpecApprovalGrant()
	grant.ApproverPrincipalIDs = []string{grant.RequestingPrincipalID}
	if err := grant.Validate(); !errors.Is(err, ErrGeneratedSpecApprovalGrantInvalid) {
		t.Fatalf("Validate(self approval) error = %v, want invalid", err)
	}
	grant = validGeneratedSpecApprovalGrant()
	grant.ApproverPrincipalIDs = []string{"user:z", "user:a"}
	if err := grant.Validate(); !errors.Is(err, ErrGeneratedSpecApprovalGrantInvalid) {
		t.Fatalf("Validate(unordered approvers) error = %v, want invalid", err)
	}
}

func TestGeneratedSpecApprovalGrantSealsAndChecksActiveWindow(t *testing.T) {
	grant := validGeneratedSpecApprovalGrant()
	sealed, err := grant.Seal()
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if err := sealed.ValidateAt(sealed.IssuedAt); err != nil {
		t.Fatalf("ValidateAt(issued) error = %v", err)
	}
	if err := sealed.ValidateAt(sealed.ExpiresAt); !errors.Is(err, ErrGeneratedSpecApprovalGrantInactive) {
		t.Fatalf("ValidateAt(expired) error = %v, want inactive", err)
	}
	sealed.WriteSetHash = sha256Ref("b")
	if err := sealed.ValidateAt(sealed.IssuedAt); !errors.Is(err, ErrGeneratedSpecApprovalGrantIntegrity) {
		t.Fatalf("ValidateAt(tampered) error = %v, want integrity", err)
	}
}

func TestGeneratedSpecApprovalConsumptionMustProjectExactGrant(t *testing.T) {
	grant, err := validGeneratedSpecApprovalGrant().Seal()
	if err != nil {
		t.Fatalf("grant Seal() error = %v", err)
	}
	consumption, err := generatedSpecApprovalConsumptionFor(grant).Seal()
	if err != nil {
		t.Fatalf("consumption Seal() error = %v", err)
	}
	if err := consumption.ValidateGrant(grant); err != nil {
		t.Fatalf("ValidateGrant() error = %v", err)
	}

	consumption.ExecutionPlanHash = sha256Ref("9")
	if err := consumption.ValidateGrant(grant); !errors.Is(err, ErrGeneratedSpecApprovalGrantIntegrity) {
		t.Fatalf("ValidateGrant(tampered) error = %v, want integrity", err)
	}
}

func validGeneratedSpecApprovalChallenge() GeneratedSpecApprovalChallenge {
	issuedAt := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	return GeneratedSpecApprovalChallenge{
		Domain: GeneratedSpecApprovalChallengeDomainV1, SchemaVersion: GeneratedSpecApprovalChallengeSchemaV1,
		ContractVersion: GeneratedSpecApprovalChallengeContractV1,
		ChallengeID:     "generated-spec-challenge-a", ApprovalID: "generated-spec-approval-a",
		TenantID: "tenant-a", WorkspaceID: "workspace-a", Audience: GeneratedSpecApprovalAudienceV1,
		GeneratedSpecID: "generated-spec-a", GeneratedSpecHash: sha256Ref("a"),
		ExecutionPlanHash: sha256Ref("b"), PlanTransactionHash: sha256Ref("c"), WriteSetHash: sha256Ref("d"),
		VerificationScopeHash: sha256Ref("e"), PolicyEnvelopeHash: sha256Ref("f"),
		PolicyVersion: "policy-v1", PolicyEpoch: "epoch-1", Action: GeneratedSpecApprovalActionV1,
		RequestingPrincipalID: "user:requester-a", AuthoritySource: "authority-a", AuthorityVersion: "version-a",
		AuthoritySnapshotHash: sha256Ref("0"), RequiredRole: "generated-spec-approver", Quorum: 1,
		ServerIdentity: "spiffe://helm/kernel-a", HoldStartedAt: issuedAt.Add(-time.Minute), EligibleAt: issuedAt.Add(-time.Second),
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(5 * time.Minute), Nonce: repeatHex("1"),
	}
}

func validGeneratedSpecApprovalGrant() GeneratedSpecApprovalGrant {
	challenge, err := validGeneratedSpecApprovalChallenge().Seal()
	if err != nil {
		panic(err)
	}
	return GeneratedSpecApprovalGrant{
		Domain: GeneratedSpecApprovalGrantDomainV1, SchemaVersion: GeneratedSpecApprovalGrantSchemaV1,
		ContractVersion: GeneratedSpecApprovalGrantContractV1,
		GrantID:         "generated-spec-grant-a", TenantID: challenge.TenantID, WorkspaceID: challenge.WorkspaceID,
		Audience: challenge.Audience, GeneratedSpecID: challenge.GeneratedSpecID, GeneratedSpecHash: challenge.GeneratedSpecHash,
		ExecutionPlanHash: challenge.ExecutionPlanHash, PlanTransactionHash: challenge.PlanTransactionHash,
		WriteSetHash: challenge.WriteSetHash, VerificationScopeHash: challenge.VerificationScopeHash,
		PolicyEnvelopeHash: challenge.PolicyEnvelopeHash, PolicyVersion: challenge.PolicyVersion, PolicyEpoch: challenge.PolicyEpoch,
		Action: challenge.Action, RequestingPrincipalID: challenge.RequestingPrincipalID,
		ApproverPrincipalIDs: []string{"user:approver-a"}, ApprovalID: challenge.ApprovalID,
		ChallengeHash: challenge.ChallengeHash, CeremonyHash: sha256Ref("2"), SignerSetHash: sha256Ref("3"),
		AuthoritySource: challenge.AuthoritySource, AuthorityVersion: challenge.AuthorityVersion,
		AuthoritySnapshotHash: challenge.AuthoritySnapshotHash, ServerIdentity: challenge.ServerIdentity,
		KernelTrustRootID: "kernel-root-a", SigningKeyRef: "kms://helm/generated-spec-a",
		IssuedAt: challenge.IssuedAt, ExpiresAt: challenge.ExpiresAt, Nonce: repeatHex("4"),
	}
}

func generatedSpecApprovalConsumptionFor(grant GeneratedSpecApprovalGrant) GeneratedSpecApprovalConsumption {
	return GeneratedSpecApprovalConsumption{
		Domain: GeneratedSpecApprovalConsumptionDomainV1, SchemaVersion: GeneratedSpecApprovalConsumptionSchemaV1,
		ContractVersion: GeneratedSpecApprovalConsumptionContractV1,
		ApprovalID:      grant.ApprovalID, GrantID: grant.GrantID, GrantHash: grant.GrantHash,
		TenantID: grant.TenantID, WorkspaceID: grant.WorkspaceID, Audience: grant.Audience, ConsumedBy: "spiffe://helm/control-plane-a",
		GeneratedSpecID: grant.GeneratedSpecID, GeneratedSpecHash: grant.GeneratedSpecHash, ExecutionPlanHash: grant.ExecutionPlanHash,
		PlanTransactionHash: grant.PlanTransactionHash, WriteSetHash: grant.WriteSetHash, VerificationScopeHash: grant.VerificationScopeHash,
		PolicyEnvelopeHash: grant.PolicyEnvelopeHash, PolicyVersion: grant.PolicyVersion, PolicyEpoch: grant.PolicyEpoch,
		Action: grant.Action, RequestingPrincipalID: grant.RequestingPrincipalID, ApproverPrincipalIDs: append([]string(nil), grant.ApproverPrincipalIDs...),
		ChallengeHash: grant.ChallengeHash, CeremonyHash: grant.CeremonyHash, SignerSetHash: grant.SignerSetHash,
		AuthoritySource: grant.AuthoritySource, AuthorityVersion: grant.AuthorityVersion, AuthoritySnapshotHash: grant.AuthoritySnapshotHash,
		ServerIdentity: grant.ServerIdentity, KernelTrustRootID: grant.KernelTrustRootID, SigningKeyRef: grant.SigningKeyRef,
		GrantIssuedAt: grant.IssuedAt, GrantExpiresAt: grant.ExpiresAt, ConsumedAt: grant.IssuedAt.Add(time.Minute),
	}
}
