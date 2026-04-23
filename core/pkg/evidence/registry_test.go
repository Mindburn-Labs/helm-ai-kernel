package evidence

import (
	"context"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func testManifest() *contracts.EvidenceContractManifest {
	return &contracts.EvidenceContractManifest{
		Version: "1.0.0",
		Contracts: []contracts.EvidenceContract{
			{
				ContractID:  "EC-001",
				ActionClass: "FUNDS_TRANSFER",
				Version:     "1.0.0",
				UpdatedAt:   time.Now(),
				Requirements: []contracts.EvidenceSpec{
					{
						EvidenceType: "receipt",
						When:         "after",
						Required:     true,
						Description:  "Transaction receipt from payment provider",
					},
					{
						EvidenceType:     "dual_attestation",
						When:             "before",
						Required:         true,
						IssuerConstraint: "finance-system",
						Description:      "Dual attestation from finance system",
					},
				},
			},
			{
				ContractID:  "EC-002",
				ActionClass: "DEPLOY",
				Version:     "1.0.0",
				UpdatedAt:   time.Now(),
				Requirements: []contracts.EvidenceSpec{
					{
						EvidenceType: "hash_proof",
						When:         "before",
						Required:     true,
						Description:  "Build artifact hash proof",
					},
				},
			},
			{
				ContractID:  "EC-003",
				ActionClass: "DATA_WRITE",
				Version:     "1.0.0",
				UpdatedAt:   time.Now(),
				Requirements: []contracts.EvidenceSpec{
					{
						EvidenceType: "receipt",
						When:         "both",
						Required:     true,
						Description:  "Write receipt for audit",
					},
				},
			},
		},
		UpdatedAt: time.Now(),
	}
}

func TestNoContractMeansSatisfied(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadManifest(testManifest()); err != nil {
		t.Fatal(err)
	}

	// NOTIFY has no contract → satisfied
	verdict, err := reg.CheckBefore(context.Background(), "NOTIFY", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Satisfied {
		t.Fatal("expected satisfied for action with no contract")
	}
}

func TestCheckBeforeSatisfied(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadManifest(testManifest()); err != nil {
		t.Fatal(err)
	}

	submissions := []contracts.EvidenceSubmission{
		{
			SubmissionID: "sub-001",
			ContractID:   "EC-001",
			ActionClass:  "FUNDS_TRANSFER",
			EvidenceType: "dual_attestation",
			ContentHash:  "sha256:abc",
			IssuerID:     "finance-system",
			SubmittedAt:  time.Now(),
			Verified:     true,
		},
	}

	verdict, err := reg.CheckBefore(context.Background(), "FUNDS_TRANSFER", submissions)
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Satisfied {
		t.Fatalf("expected satisfied, missing: %v", verdict.Missing)
	}
}

func TestCheckBeforeMissing(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadManifest(testManifest()); err != nil {
		t.Fatal(err)
	}

	// No submissions → "before" requirement unsatisfied
	verdict, err := reg.CheckBefore(context.Background(), "FUNDS_TRANSFER", nil)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Satisfied {
		t.Fatal("expected unsatisfied without evidence")
	}
	if len(verdict.Missing) != 1 {
		t.Fatalf("expected 1 missing, got %d", len(verdict.Missing))
	}
	if verdict.Missing[0].EvidenceType != "dual_attestation" {
		t.Fatalf("expected dual_attestation missing, got %s", verdict.Missing[0].EvidenceType)
	}
}

func TestCheckAfterSatisfied(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadManifest(testManifest()); err != nil {
		t.Fatal(err)
	}

	submissions := []contracts.EvidenceSubmission{
		{
			SubmissionID: "sub-002",
			ContractID:   "EC-001",
			ActionClass:  "FUNDS_TRANSFER",
			EvidenceType: "receipt",
			ContentHash:  "sha256:def",
			IssuerID:     "payment-gateway",
			SubmittedAt:  time.Now(),
			Verified:     true,
		},
	}

	verdict, err := reg.CheckAfter(context.Background(), "FUNDS_TRANSFER", submissions)
	if err != nil {
		t.Fatal(err)
	}
	if !verdict.Satisfied {
		t.Fatalf("expected satisfied, missing: %v", verdict.Missing)
	}
}

func TestCheckBothPhase(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadManifest(testManifest()); err != nil {
		t.Fatal(err)
	}

	// DATA_WRITE requires receipt at "both" phases
	// Check before without evidence
	verdict, err := reg.CheckBefore(context.Background(), "DATA_WRITE", nil)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Satisfied {
		t.Fatal("expected unsatisfied for DATA_WRITE before without evidence")
	}

	// Check after without evidence
	verdict, err = reg.CheckAfter(context.Background(), "DATA_WRITE", nil)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Satisfied {
		t.Fatal("expected unsatisfied for DATA_WRITE after without evidence")
	}
}

func TestIssuerConstraintEnforced(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadManifest(testManifest()); err != nil {
		t.Fatal(err)
	}

	// Submit with wrong issuer
	submissions := []contracts.EvidenceSubmission{
		{
			SubmissionID: "sub-003",
			EvidenceType: "dual_attestation",
			IssuerID:     "wrong-issuer",
			Verified:     true,
		},
	}

	verdict, err := reg.CheckBefore(context.Background(), "FUNDS_TRANSFER", submissions)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Satisfied {
		t.Fatal("expected unsatisfied with wrong issuer")
	}
}

func TestUnverifiedEvidenceNotCounted(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadManifest(testManifest()); err != nil {
		t.Fatal(err)
	}

	// Submit unverified evidence
	submissions := []contracts.EvidenceSubmission{
		{
			SubmissionID: "sub-004",
			EvidenceType: "hash_proof",
			IssuerID:     "build-system",
			Verified:     false, // Not verified!
		},
	}

	verdict, err := reg.CheckBefore(context.Background(), "DEPLOY", submissions)
	if err != nil {
		t.Fatal(err)
	}
	if verdict.Satisfied {
		t.Fatal("expected unsatisfied with unverified evidence")
	}
}

func TestManifestVersionTracking(t *testing.T) {
	reg := NewRegistry()
	if reg.ManifestVersion() != "unloaded" {
		t.Fatal("expected 'unloaded'")
	}
	if err := reg.LoadManifest(testManifest()); err != nil {
		t.Fatal(err)
	}
	if reg.ManifestVersion() != "1.0.0" {
		t.Fatalf("expected '1.0.0', got %q", reg.ManifestVersion())
	}
}

func TestGetContractReturnsNilForUnknown(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadManifest(testManifest()); err != nil {
		t.Fatal(err)
	}
	if reg.GetContract("UNKNOWN") != nil {
		t.Fatal("expected nil for unknown action class")
	}
}

func TestManifestHashDeterminism(t *testing.T) {
	m := testManifest()
	h1, err := ComputeManifestHash(m)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ComputeManifestHash(m)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("manifest hash not deterministic: %q != %q", h1, h2)
	}
}
