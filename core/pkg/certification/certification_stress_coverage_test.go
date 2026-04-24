package certification

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/vcredentials"
)

var stressClock = func() time.Time { return time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC) }

func stressBadgeIssuer(t *testing.T) *BadgeIssuer {
	t.Helper()
	signer, err := crypto.NewEd25519Signer("stress-cert-key")
	if err != nil {
		t.Fatal(err)
	}
	vcIssuer := vcredentials.NewIssuerWithClock("did:helm:stress", "Stress Instance", signer, stressClock)
	framework := NewFramework().WithClock(stressClock)
	return NewBadgeIssuer(vcIssuer, framework)
}

// --- Evaluate at Every Level Boundary (+/-1) ---

func TestStress_Evaluate_BronzeExactThreshold(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 400, ComplianceScore: 60, ObservationDays: 7, ViolationCount: 10})
	if !r.Passed || r.Level != CertBronze {
		t.Fatalf("expected BRONZE pass, got %s passed=%v", r.Level, r.Passed)
	}
}

func TestStress_Evaluate_BronzeBelowTrust(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 399, ComplianceScore: 60, ObservationDays: 7, ViolationCount: 10})
	if r.Passed {
		t.Fatal("expected fail below BRONZE trust threshold")
	}
}

func TestStress_Evaluate_BronzeBelowCompliance(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 400, ComplianceScore: 59, ObservationDays: 7, ViolationCount: 10})
	if r.Passed {
		t.Fatal("expected fail below BRONZE compliance threshold")
	}
}

func TestStress_Evaluate_BronzeBelowObservation(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 400, ComplianceScore: 60, ObservationDays: 6, ViolationCount: 10})
	if r.Passed {
		t.Fatal("expected fail below BRONZE observation days")
	}
}

func TestStress_Evaluate_BronzeAboveViolations(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 400, ComplianceScore: 60, ObservationDays: 7, ViolationCount: 11})
	if r.Passed {
		t.Fatal("expected fail exceeding BRONZE max violations")
	}
}

func TestStress_Evaluate_SilverExactThreshold(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 600, ComplianceScore: 80, ObservationDays: 30, ViolationCount: 5})
	if !r.Passed || r.Level != CertSilver {
		t.Fatalf("expected SILVER pass, got %s passed=%v", r.Level, r.Passed)
	}
}

func TestStress_Evaluate_SilverBelowTrust(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 599, ComplianceScore: 80, ObservationDays: 30, ViolationCount: 5})
	if r.Level == CertSilver {
		t.Fatal("expected not SILVER with trust 599")
	}
}

func TestStress_Evaluate_GoldExactThreshold(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 700, ComplianceScore: 90, ObservationDays: 60, ViolationCount: 2, HasAIBOM: true})
	if !r.Passed || r.Level != CertGold {
		t.Fatalf("expected GOLD pass, got %s passed=%v", r.Level, r.Passed)
	}
}

func TestStress_Evaluate_GoldMissingAIBOM(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 700, ComplianceScore: 90, ObservationDays: 60, ViolationCount: 2, HasAIBOM: false})
	if r.Level == CertGold {
		t.Fatal("expected not GOLD without AIBOM")
	}
}

func TestStress_Evaluate_PlatinumExactThreshold(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 800, ComplianceScore: 95, ObservationDays: 90, ViolationCount: 0, HasAIBOM: true, HasZKProof: true})
	if !r.Passed || r.Level != CertPlatinum {
		t.Fatalf("expected PLATINUM pass, got %s passed=%v", r.Level, r.Passed)
	}
}

func TestStress_Evaluate_PlatinumMissingZK(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 800, ComplianceScore: 95, ObservationDays: 90, ViolationCount: 0, HasAIBOM: true, HasZKProof: false})
	if r.Level == CertPlatinum {
		t.Fatal("expected not PLATINUM without ZK proof")
	}
}

func TestStress_Evaluate_PlatinumOneViolation(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 800, ComplianceScore: 95, ObservationDays: 90, ViolationCount: 1, HasAIBOM: true, HasZKProof: true})
	if r.Level == CertPlatinum {
		t.Fatal("expected not PLATINUM with 1 violation")
	}
}

// --- Badge Issuance 50 Agents ---

func TestStress_Badge_Issue50Agents(t *testing.T) {
	issuer := stressBadgeIssuer(t)
	for i := 0; i < 50; i++ {
		vc, result, err := issuer.IssueBadge(
			fmt.Sprintf("agent-%d", i),
			fmt.Sprintf("did:helm:agent-%d", i),
			CertificationScores{TrustScore: 600, ComplianceScore: 80, ObservationDays: 30, ViolationCount: 5},
			24*time.Hour,
		)
		if err != nil {
			t.Fatalf("agent %d: badge error: %v", i, err)
		}
		if !result.Passed {
			t.Fatalf("agent %d: expected pass", i)
		}
		if vc == nil {
			t.Fatalf("agent %d: expected VC", i)
		}
	}
}

func TestStress_Badge_FailingAgent(t *testing.T) {
	issuer := stressBadgeIssuer(t)
	vc, result, err := issuer.IssueBadge("fail-agent", "did:helm:fail", CertificationScores{TrustScore: 100}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed {
		t.Fatal("expected failing agent")
	}
	if vc != nil {
		t.Fatal("expected nil VC for failing agent")
	}
}

func TestStress_Badge_PlatinumAgent(t *testing.T) {
	issuer := stressBadgeIssuer(t)
	vc, result, _ := issuer.IssueBadge("plat-agent", "did:helm:plat",
		CertificationScores{TrustScore: 900, ComplianceScore: 99, ObservationDays: 100, ViolationCount: 0, HasAIBOM: true, HasZKProof: true},
		24*time.Hour)
	if !result.Passed || result.Level != CertPlatinum {
		t.Fatal("expected PLATINUM")
	}
	if vc == nil {
		t.Fatal("expected VC for platinum agent")
	}
}

// --- Concurrent Evaluation 50 Goroutines ---

func TestStress_Concurrent_Evaluate50(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			r := f.Evaluate(fmt.Sprintf("agent-%d", id), CertificationScores{
				TrustScore: 500, ComplianceScore: 70, ObservationDays: 15, ViolationCount: 8,
			})
			if !r.Passed {
				t.Errorf("agent %d should pass BRONZE", id)
			}
		}(i)
	}
	wg.Wait()
}

func TestStress_Concurrent_BadgeIssue50(t *testing.T) {
	issuer := stressBadgeIssuer(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			_, _, err := issuer.IssueBadge(
				fmt.Sprintf("ca-%d", id), fmt.Sprintf("did:helm:ca-%d", id),
				CertificationScores{TrustScore: 600, ComplianceScore: 80, ObservationDays: 30, ViolationCount: 5},
				24*time.Hour,
			)
			if err != nil {
				t.Errorf("concurrent badge %d: %v", id, err)
			}
		}(i)
	}
	wg.Wait()
}

// --- Custom Criteria for Each Level ---

func TestStress_CustomCriteria_Bronze(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	f.SetCriteria(CertBronze, CertificationCriteria{MinTrustScore: 100, MinComplianceScore: 30, MinObservationDays: 1, MaxViolations: 50})
	r := f.Evaluate("a1", CertificationScores{TrustScore: 100, ComplianceScore: 30, ObservationDays: 1, ViolationCount: 50})
	if !r.Passed {
		t.Fatal("expected pass with custom bronze criteria")
	}
}

func TestStress_CustomCriteria_Silver(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	f.SetCriteria(CertSilver, CertificationCriteria{MinTrustScore: 500, MinComplianceScore: 70, MinObservationDays: 20, MaxViolations: 8})
	r := f.Evaluate("a1", CertificationScores{TrustScore: 500, ComplianceScore: 70, ObservationDays: 20, ViolationCount: 8})
	if !r.Passed || r.Level != CertSilver {
		t.Fatalf("expected SILVER with custom criteria, got %s", r.Level)
	}
}

func TestStress_CustomCriteria_Gold(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	f.SetCriteria(CertGold, CertificationCriteria{MinTrustScore: 650, MinComplianceScore: 85, MinObservationDays: 45, MaxViolations: 3})
	r := f.Evaluate("a1", CertificationScores{TrustScore: 650, ComplianceScore: 85, ObservationDays: 45, ViolationCount: 3})
	if !r.Passed || r.Level != CertGold {
		t.Fatalf("expected GOLD with custom criteria, got %s", r.Level)
	}
}

func TestStress_CustomCriteria_Platinum(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	f.SetCriteria(CertPlatinum, CertificationCriteria{MinTrustScore: 750, MinComplianceScore: 90, MinObservationDays: 60, MaxViolations: 0})
	r := f.Evaluate("a1", CertificationScores{TrustScore: 750, ComplianceScore: 90, ObservationDays: 60, ViolationCount: 0})
	if !r.Passed || r.Level != CertPlatinum {
		t.Fatalf("expected PLATINUM with custom criteria, got %s", r.Level)
	}
}

func TestStress_GetCriteria_Exists(t *testing.T) {
	f := NewFramework()
	c, ok := f.GetCriteria(CertBronze)
	if !ok {
		t.Fatal("expected BRONZE criteria to exist")
	}
	if c.MinTrustScore != 400 {
		t.Fatalf("expected 400 min trust, got %d", c.MinTrustScore)
	}
}

func TestStress_GetCriteria_Unknown(t *testing.T) {
	f := NewFramework()
	_, ok := f.GetCriteria(CertificationLevel("DIAMOND"))
	if ok {
		t.Fatal("expected unknown level to not exist")
	}
}

// --- Content Hash Determinism 100 Iterations ---

func TestStress_ContentHash_Determinism100(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	scores := CertificationScores{TrustScore: 600, ComplianceScore: 80, ObservationDays: 30, ViolationCount: 5}
	first := f.Evaluate("det-agent", scores)
	for i := 0; i < 100; i++ {
		r := f.Evaluate("det-agent", scores)
		if r.ContentHash != first.ContentHash {
			t.Fatalf("content hash changed at iteration %d", i)
		}
	}
}

func TestStress_ContentHash_DiffersAcrossLevels(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	bronze := f.Evaluate("a1", CertificationScores{TrustScore: 400, ComplianceScore: 60, ObservationDays: 7, ViolationCount: 10})
	silver := f.Evaluate("a1", CertificationScores{TrustScore: 600, ComplianceScore: 80, ObservationDays: 30, ViolationCount: 5})
	if bronze.ContentHash == silver.ContentHash {
		t.Fatal("different levels should produce different content hashes")
	}
}

func TestStress_ContentHash_DiffersAcrossAgents(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	scores := CertificationScores{TrustScore: 600, ComplianceScore: 80, ObservationDays: 30, ViolationCount: 5}
	r1 := f.Evaluate("agent-x", scores)
	r2 := f.Evaluate("agent-y", scores)
	if r1.ContentHash == r2.ContentHash {
		t.Fatal("different agents should produce different content hashes")
	}
}

func TestStress_Evaluate_ResultIDFormat(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("fmt-agent", CertificationScores{TrustScore: 500, ComplianceScore: 70, ObservationDays: 10, ViolationCount: 8})
	if r.ResultID == "" {
		t.Fatal("result ID should not be empty")
	}
}

func TestStress_Evaluate_FailReasonSet(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("fail-agent", CertificationScores{TrustScore: 0})
	if r.Passed {
		t.Fatal("expected failure")
	}
	if r.Reason == "" {
		t.Fatal("expected failure reason to be set")
	}
}

func TestStress_Evaluate_ScoresPreserved(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	scores := CertificationScores{TrustScore: 777, ComplianceScore: 88, ObservationDays: 45, ViolationCount: 3, HasAIBOM: true}
	r := f.Evaluate("a1", scores)
	if r.Scores.TrustScore != 777 {
		t.Fatalf("trust score not preserved: %d", r.Scores.TrustScore)
	}
}

func TestStress_Evaluate_GoldBelowTrust(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 699, ComplianceScore: 90, ObservationDays: 60, ViolationCount: 2, HasAIBOM: true})
	if r.Level == CertGold {
		t.Fatal("expected not GOLD with trust 699")
	}
}

func TestStress_Evaluate_SilverBelowCompliance(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 600, ComplianceScore: 79, ObservationDays: 30, ViolationCount: 5})
	if r.Level == CertSilver {
		t.Fatal("expected not SILVER with compliance 79")
	}
}

func TestStress_Evaluate_PlatinumBelowTrust(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 799, ComplianceScore: 95, ObservationDays: 90, ViolationCount: 0, HasAIBOM: true, HasZKProof: true})
	if r.Level == CertPlatinum {
		t.Fatal("expected not PLATINUM with trust 799")
	}
}

func TestStress_Badge_BronzeAgent(t *testing.T) {
	issuer := stressBadgeIssuer(t)
	vc, result, _ := issuer.IssueBadge("bronze-agent", "did:helm:bronze",
		CertificationScores{TrustScore: 400, ComplianceScore: 60, ObservationDays: 7, ViolationCount: 10},
		24*time.Hour)
	if !result.Passed || result.Level != CertBronze {
		t.Fatal("expected BRONZE")
	}
	if vc == nil {
		t.Fatal("expected VC for bronze agent")
	}
}

func TestStress_Badge_SilverAgent(t *testing.T) {
	issuer := stressBadgeIssuer(t)
	vc, result, _ := issuer.IssueBadge("silver-agent", "did:helm:silver",
		CertificationScores{TrustScore: 600, ComplianceScore: 80, ObservationDays: 30, ViolationCount: 5},
		24*time.Hour)
	if !result.Passed || result.Level != CertSilver {
		t.Fatal("expected SILVER")
	}
	if vc == nil {
		t.Fatal("expected VC for silver agent")
	}
}

func TestStress_Badge_GoldAgent(t *testing.T) {
	issuer := stressBadgeIssuer(t)
	vc, result, _ := issuer.IssueBadge("gold-agent", "did:helm:gold",
		CertificationScores{TrustScore: 700, ComplianceScore: 90, ObservationDays: 60, ViolationCount: 2, HasAIBOM: true},
		24*time.Hour)
	if !result.Passed || result.Level != CertGold {
		t.Fatal("expected GOLD")
	}
	if vc == nil {
		t.Fatal("expected VC for gold agent")
	}
}

func TestStress_Evaluate_HighestLevelSelected(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 900, ComplianceScore: 99, ObservationDays: 100, ViolationCount: 0, HasAIBOM: true, HasZKProof: true})
	if r.Level != CertPlatinum {
		t.Fatalf("expected PLATINUM (highest matching), got %s", r.Level)
	}
}

func TestStress_Evaluate_CriteriaInResult(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 600, ComplianceScore: 80, ObservationDays: 30, ViolationCount: 5})
	if r.Criteria.Level != CertSilver {
		t.Fatalf("expected criteria level SILVER, got %s", r.Criteria.Level)
	}
}

func TestStress_Evaluate_AgentIDPreserved(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("my-special-agent", CertificationScores{TrustScore: 500, ComplianceScore: 70, ObservationDays: 10, ViolationCount: 8})
	if r.AgentID != "my-special-agent" {
		t.Fatalf("agent ID not preserved: %s", r.AgentID)
	}
}

func TestStress_Evaluate_GoldAboveViolations(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 700, ComplianceScore: 90, ObservationDays: 60, ViolationCount: 3, HasAIBOM: true})
	if r.Level == CertGold {
		t.Fatal("expected not GOLD with 3 violations (max 2)")
	}
}

func TestStress_Evaluate_EvaluatedAtSet(t *testing.T) {
	f := NewFramework().WithClock(stressClock)
	r := f.Evaluate("a1", CertificationScores{TrustScore: 500, ComplianceScore: 70, ObservationDays: 10, ViolationCount: 8})
	if r.EvaluatedAt.IsZero() {
		t.Fatal("expected evaluated_at to be set")
	}
}
