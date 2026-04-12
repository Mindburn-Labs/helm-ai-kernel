package certification

import (
	"testing"
	"time"
)

var fixedClock = func() time.Time {
	return time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)
}

func TestFramework_EvaluateBronze(t *testing.T) {
	f := NewFramework().WithClock(fixedClock)

	scores := CertificationScores{
		TrustScore:      450,
		ComplianceScore: 65,
		ObservationDays: 10,
		ViolationCount:  3,
		HasAIBOM:        false,
		HasZKProof:      false,
	}

	result := f.Evaluate("agent-bronze", scores)

	if !result.Passed {
		t.Fatalf("expected agent to pass, got failed: %s", result.Reason)
	}
	if result.Level != CertBronze {
		t.Fatalf("expected BRONZE, got %s", result.Level)
	}
	if result.AgentID != "agent-bronze" {
		t.Fatalf("expected agent-bronze, got %s", result.AgentID)
	}
	if result.ContentHash == "" || result.ContentHash == "hash-error" {
		t.Fatal("expected valid content hash")
	}
}

func TestFramework_EvaluateGold(t *testing.T) {
	f := NewFramework().WithClock(fixedClock)

	// Scores meet GOLD but not PLATINUM (no ZK proof, only 60 observation days).
	scores := CertificationScores{
		TrustScore:      750,
		ComplianceScore: 92,
		ObservationDays: 65,
		ViolationCount:  1,
		HasAIBOM:        true,
		HasZKProof:      false,
	}

	result := f.Evaluate("agent-gold", scores)

	if !result.Passed {
		t.Fatalf("expected agent to pass, got failed: %s", result.Reason)
	}
	if result.Level != CertGold {
		t.Fatalf("expected GOLD, got %s", result.Level)
	}
}

func TestFramework_EvaluateFail(t *testing.T) {
	f := NewFramework().WithClock(fixedClock)

	// Trust too low, compliance too low, not enough observation days.
	scores := CertificationScores{
		TrustScore:      200,
		ComplianceScore: 30,
		ObservationDays: 2,
		ViolationCount:  15,
		HasAIBOM:        false,
		HasZKProof:      false,
	}

	result := f.Evaluate("agent-fail", scores)

	if result.Passed {
		t.Fatal("expected agent to fail certification")
	}
	if result.Level != CertBronze {
		t.Fatalf("expected failure level to be BRONZE, got %s", result.Level)
	}
	if result.Reason == "" {
		t.Fatal("expected failure reason to be populated")
	}
}

func TestFramework_HighestLevel(t *testing.T) {
	f := NewFramework().WithClock(fixedClock)

	// Scores meet ALL levels including PLATINUM.
	scores := CertificationScores{
		TrustScore:      900,
		ComplianceScore: 99,
		ObservationDays: 120,
		ViolationCount:  0,
		HasAIBOM:        true,
		HasZKProof:      true,
	}

	result := f.Evaluate("agent-platinum", scores)

	if !result.Passed {
		t.Fatalf("expected agent to pass, got failed: %s", result.Reason)
	}
	if result.Level != CertPlatinum {
		t.Fatalf("expected PLATINUM (highest qualifying), got %s", result.Level)
	}
}

func TestFramework_CustomCriteria(t *testing.T) {
	f := NewFramework().WithClock(fixedClock)

	// Override BRONZE to require higher trust.
	f.SetCriteria(CertBronze, CertificationCriteria{
		MinTrustScore:      500,
		MinComplianceScore: 70,
		MinObservationDays: 14,
		MaxViolations:      5,
	})

	// Agent meets old BRONZE but not new custom BRONZE.
	scores := CertificationScores{
		TrustScore:      450,
		ComplianceScore: 65,
		ObservationDays: 10,
		ViolationCount:  3,
	}

	result := f.Evaluate("agent-custom", scores)

	if result.Passed {
		t.Fatal("expected agent to fail with custom (stricter) BRONZE criteria")
	}

	// Verify GetCriteria reflects the override.
	criteria, ok := f.GetCriteria(CertBronze)
	if !ok {
		t.Fatal("expected BRONZE criteria to exist")
	}
	if criteria.MinTrustScore != 500 {
		t.Fatalf("expected MinTrustScore 500, got %d", criteria.MinTrustScore)
	}
}

func TestFramework_PlatinumRequiresZK(t *testing.T) {
	f := NewFramework().WithClock(fixedClock)

	// All scores are platinum-worthy except no ZK proof.
	scores := CertificationScores{
		TrustScore:      900,
		ComplianceScore: 99,
		ObservationDays: 120,
		ViolationCount:  0,
		HasAIBOM:        true,
		HasZKProof:      false, // Missing ZK proof.
	}

	result := f.Evaluate("agent-no-zk", scores)

	if !result.Passed {
		t.Fatalf("expected agent to pass at some level, got failed: %s", result.Reason)
	}
	// Should qualify for GOLD but not PLATINUM.
	if result.Level == CertPlatinum {
		t.Fatal("expected agent NOT to reach PLATINUM without ZK proof")
	}
	if result.Level != CertGold {
		t.Fatalf("expected GOLD (highest without ZK), got %s", result.Level)
	}
}

func TestFramework_SilverLevel(t *testing.T) {
	f := NewFramework().WithClock(fixedClock)

	// Meets SILVER but not GOLD (no AIBOM, trust below 700).
	scores := CertificationScores{
		TrustScore:      650,
		ComplianceScore: 85,
		ObservationDays: 35,
		ViolationCount:  4,
		HasAIBOM:        false,
		HasZKProof:      false,
	}

	result := f.Evaluate("agent-silver", scores)

	if !result.Passed {
		t.Fatalf("expected agent to pass, got failed: %s", result.Reason)
	}
	if result.Level != CertSilver {
		t.Fatalf("expected SILVER, got %s", result.Level)
	}
}

func TestFramework_ContentHashDeterministic(t *testing.T) {
	f := NewFramework().WithClock(fixedClock)

	scores := CertificationScores{
		TrustScore:      500,
		ComplianceScore: 70,
		ObservationDays: 14,
		ViolationCount:  2,
	}

	r1 := f.Evaluate("agent-hash", scores)
	r2 := f.Evaluate("agent-hash", scores)

	if r1.ContentHash != r2.ContentHash {
		t.Fatalf("expected deterministic content hash, got %s vs %s", r1.ContentHash, r2.ContentHash)
	}
	if r1.ContentHash == "" {
		t.Fatal("expected non-empty content hash")
	}
}

func TestFramework_GetCriteria_NotFound(t *testing.T) {
	f := NewFramework()

	_, ok := f.GetCriteria(CertificationLevel("DIAMOND"))
	if ok {
		t.Fatal("expected DIAMOND level to not exist")
	}
}
