package ceremony

import (
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
)

func validBinding() contracts.GenesisApprovalBinding {
	return contracts.GenesisApprovalBinding{
		PolicyGenesisHash: "abc123def456",
		MirrorTextHash:    "aaa111bbb222",
		ImpactReportHash:  "ccc333ddd444",
		P0CeilingHash:     "eee555fff666",
	}
}

func validRequest() contracts.GenesisApprovalRequest {
	b := validBinding()
	return contracts.GenesisApprovalRequest{
		Binding:          b,
		ChallengeHash:    DeriveGenesisChallenge(b),
		Quorum:           1,
		TimelockDuration: 5 * time.Second,
		ApproverKeyIDs:   []string{"key-1"},
		Signatures:       []string{"sig-1"},
		SubmittedAt:      time.Now(),
	}
}

func TestValidGenesisApproval(t *testing.T) {
	result := ValidateGenesisApproval(validRequest())
	if !result.Valid {
		t.Fatalf("expected valid, got reason: %s", result.Reason)
	}
	if result.ElevatedRisk {
		t.Fatal("expected no elevated risk")
	}
}

func TestMissingPolicyGenesisHash(t *testing.T) {
	req := validRequest()
	req.Binding.PolicyGenesisHash = ""
	// Must recompute challenge since binding changed
	req.ChallengeHash = DeriveGenesisChallenge(req.Binding)
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("expected invalid")
	}
}

func TestMissingMirrorTextHash(t *testing.T) {
	req := validRequest()
	req.Binding.MirrorTextHash = ""
	req.ChallengeHash = DeriveGenesisChallenge(req.Binding)
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("expected invalid")
	}
}

func TestMissingImpactReportHash(t *testing.T) {
	req := validRequest()
	req.Binding.ImpactReportHash = ""
	req.ChallengeHash = DeriveGenesisChallenge(req.Binding)
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("expected invalid")
	}
}

func TestMissingP0CeilingHash(t *testing.T) {
	req := validRequest()
	req.Binding.P0CeilingHash = ""
	req.ChallengeHash = DeriveGenesisChallenge(req.Binding)
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("expected invalid")
	}
}

func TestChallengeHashMismatch(t *testing.T) {
	req := validRequest()
	req.ChallengeHash = "definitely-wrong-hash"
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("expected invalid due to challenge mismatch")
	}
}

func TestQuorumNotMet(t *testing.T) {
	req := validRequest()
	req.Quorum = 3
	// Only 1 signature
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("expected invalid due to quorum not met")
	}
}

func TestQuorumMet(t *testing.T) {
	req := validRequest()
	req.Quorum = 2
	req.ApproverKeyIDs = []string{"key-1", "key-2"}
	req.Signatures = []string{"sig-1", "sig-2"}
	result := ValidateGenesisApproval(req)
	if !result.Valid {
		t.Fatalf("expected valid, got: %s", result.Reason)
	}
}

func TestTimelockZeroDuration(t *testing.T) {
	req := validRequest()
	req.TimelockDuration = 0
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("expected invalid due to zero timelock")
	}
}

func TestEmergencyOverride(t *testing.T) {
	req := validRequest()
	req.EmergencyOverride = true
	result := ValidateGenesisApproval(req)
	if !result.Valid {
		t.Fatalf("expected valid, got: %s", result.Reason)
	}
	if !result.ElevatedRisk {
		t.Fatal("expected elevated risk for emergency override")
	}
	if !result.RequiresReview {
		t.Fatal("expected requires review for emergency override")
	}
}

func TestSignatureCountMismatch(t *testing.T) {
	req := validRequest()
	req.ApproverKeyIDs = []string{"key-1", "key-2"}
	req.Signatures = []string{"sig-1"}
	result := ValidateGenesisApproval(req)
	if result.Valid {
		t.Fatal("expected invalid due to signature/key count mismatch")
	}
}

func TestDeriveGenesisChallengeIsDeterministic(t *testing.T) {
	b := validBinding()
	h1 := DeriveGenesisChallenge(b)
	h2 := DeriveGenesisChallenge(b)
	if h1 != h2 {
		t.Fatalf("challenge should be deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64 hex chars, got %d", len(h1))
	}
}
