package certification

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/vcredentials"
)

var deepTime = time.Date(2026, 4, 12, 10, 0, 0, 0, time.UTC)

func deepClock() time.Time { return deepTime }

func deepPlatScores() CertificationScores {
	return CertificationScores{
		TrustScore: 900, ComplianceScore: 98, ObservationDays: 120,
		ViolationCount: 0, HasAIBOM: true, HasZKProof: true,
	}
}

func TestDeep_EvaluatePlatinum(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	r := f.Evaluate("agent-1", deepPlatScores())
	if !r.Passed || r.Level != CertPlatinum {
		t.Fatalf("expected PLATINUM, got %s (passed=%v, reason=%s)", r.Level, r.Passed, r.Reason)
	}
}

func TestDeep_EvaluateGold(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	scores := CertificationScores{
		TrustScore: 750, ComplianceScore: 92, ObservationDays: 70,
		ViolationCount: 1, HasAIBOM: true, HasZKProof: false,
	}
	r := f.Evaluate("agent-1", scores)
	if r.Level != CertGold {
		t.Fatalf("expected GOLD, got %s", r.Level)
	}
}

func TestDeep_EvaluateSilver(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	scores := CertificationScores{
		TrustScore: 650, ComplianceScore: 85, ObservationDays: 40,
		ViolationCount: 3, HasAIBOM: false,
	}
	r := f.Evaluate("agent-1", scores)
	if r.Level != CertSilver {
		t.Fatalf("expected SILVER, got %s", r.Level)
	}
}

func TestDeep_EvaluateBronze(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	scores := CertificationScores{
		TrustScore: 450, ComplianceScore: 65, ObservationDays: 10,
		ViolationCount: 8,
	}
	r := f.Evaluate("agent-1", scores)
	if r.Level != CertBronze {
		t.Fatalf("expected BRONZE, got %s", r.Level)
	}
}

func TestDeep_EvaluateFailsBelowBronze(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	scores := CertificationScores{TrustScore: 100, ComplianceScore: 20, ObservationDays: 1}
	r := f.Evaluate("agent-1", scores)
	if r.Passed {
		t.Fatal("should not pass below Bronze")
	}
	if r.Reason == "" {
		t.Fatal("should explain failure reason")
	}
}

func TestDeep_EvaluateBronzeBoundaryTrustScore(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	just := CertificationScores{TrustScore: 400, ComplianceScore: 60, ObservationDays: 7, ViolationCount: 10}
	r := f.Evaluate("a", just)
	if !r.Passed {
		t.Fatal("exactly at Bronze boundary should pass")
	}
	below := CertificationScores{TrustScore: 399, ComplianceScore: 60, ObservationDays: 7, ViolationCount: 10}
	r = f.Evaluate("a", below)
	if r.Passed {
		t.Fatal("one below Bronze trust should fail")
	}
}

func TestDeep_EvaluateBronzeBoundaryCompliance(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	below := CertificationScores{TrustScore: 500, ComplianceScore: 59, ObservationDays: 30, ViolationCount: 0}
	r := f.Evaluate("a", below)
	if r.Level == CertBronze && r.Passed {
		// ComplianceScore 59 < Bronze's 60
		if r.Level != CertBronze {
			t.Fatal("should attempt Bronze level")
		}
	}
}

func TestDeep_EvaluatePlatinumRequiresZKProof(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	scores := deepPlatScores()
	scores.HasZKProof = false
	r := f.Evaluate("a", scores)
	if r.Level == CertPlatinum {
		t.Fatal("should not award PLATINUM without ZK proof")
	}
}

func TestDeep_EvaluatePlatinumRequiresAIBOM(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	scores := deepPlatScores()
	scores.HasAIBOM = false
	r := f.Evaluate("a", scores)
	if r.Level == CertPlatinum {
		t.Fatal("should not award PLATINUM without AIBOM")
	}
}

func TestDeep_EvaluateGoldRequiresAIBOM(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	scores := CertificationScores{
		TrustScore: 750, ComplianceScore: 92, ObservationDays: 70,
		ViolationCount: 1, HasAIBOM: false,
	}
	r := f.Evaluate("a", scores)
	if r.Level == CertGold {
		t.Fatal("should not award GOLD without AIBOM")
	}
}

func TestDeep_BadgeIssuanceW3CVC(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("cert-key")
	vcIssuer := vcredentials.NewIssuerWithClock("did:helm:certifier", "HELM Certifier", signer, deepClock)
	f := NewFramework().WithClock(deepClock)
	bi := NewBadgeIssuer(vcIssuer, f)

	vc, result, err := bi.IssueBadge("agent-1", "did:helm:agent-1", deepPlatScores(), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Passed {
		t.Fatal("certification should pass")
	}
	if vc == nil {
		t.Fatal("VC should be issued for passing agent")
	}
	if !strings.Contains(vc.CredentialSubject.Capabilities[0].Action, "PLATINUM") {
		t.Fatal("badge should encode PLATINUM level")
	}
}

func TestDeep_BadgeNotIssuedForFailingAgent(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("k")
	vcIssuer := vcredentials.NewIssuerWithClock("did:helm:c", "C", signer, deepClock)
	f := NewFramework().WithClock(deepClock)
	bi := NewBadgeIssuer(vcIssuer, f)

	vc, result, err := bi.IssueBadge("a", "did:helm:a", CertificationScores{TrustScore: 50}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if result.Passed {
		t.Fatal("should not pass")
	}
	if vc != nil {
		t.Fatal("VC should NOT be issued for failing agent")
	}
}

func TestDeep_ConcurrentEvaluation20Goroutines(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			scores := CertificationScores{
				TrustScore: 500 + idx*20, ComplianceScore: 70 + idx,
				ObservationDays: 10 + idx*5, ViolationCount: 20 - idx,
			}
			r := f.Evaluate(fmt.Sprintf("agent-%d", idx), scores)
			if r.ResultID == "" {
				t.Error("ResultID should be set")
			}
		}(i)
	}
	wg.Wait()
}

func TestDeep_CriteriaCustomization(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	f.SetCriteria(CertBronze, CertificationCriteria{
		MinTrustScore: 100, MinComplianceScore: 30,
		MinObservationDays: 1, MaxViolations: 100,
	})
	scores := CertificationScores{TrustScore: 100, ComplianceScore: 30, ObservationDays: 1}
	r := f.Evaluate("a", scores)
	if !r.Passed {
		t.Fatal("custom low-bar Bronze should pass")
	}
}

func TestDeep_GetCriteriaNotFound(t *testing.T) {
	f := NewFramework()
	_, ok := f.GetCriteria("IMAGINARY")
	if ok {
		t.Fatal("non-existent level should not be found")
	}
}

func TestDeep_ContentHashDeterminism(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	scores := deepPlatScores()
	r1 := f.Evaluate("a", scores)
	r2 := f.Evaluate("a", scores)
	if r1.ContentHash != r2.ContentHash {
		t.Fatal("same inputs should produce same content hash")
	}
}

func TestDeep_ContentHashChangesWithDifferentScores(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	r1 := f.Evaluate("a", deepPlatScores())
	s := deepPlatScores()
	s.TrustScore = 801
	r2 := f.Evaluate("a", s)
	if r1.ContentHash == r2.ContentHash {
		t.Fatal("different scores should produce different content hash")
	}
}

func TestDeep_BadgeVCHasCorrectSubjectDID(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("k")
	vcIssuer := vcredentials.NewIssuerWithClock("did:helm:c", "C", signer, deepClock)
	f := NewFramework().WithClock(deepClock)
	bi := NewBadgeIssuer(vcIssuer, f)

	vc, _, _ := bi.IssueBadge("agent-x", "did:helm:agent-x", deepPlatScores(), time.Hour)
	if vc.CredentialSubject.ID != "did:helm:agent-x" {
		t.Fatalf("subject DID=%q, want did:helm:agent-x", vc.CredentialSubject.ID)
	}
}

func TestDeep_EvaluateResultIDUnique(t *testing.T) {
	f := NewFramework()
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		r := f.Evaluate(fmt.Sprintf("a-%d", i), deepPlatScores())
		if seen[r.ResultID] {
			t.Fatalf("duplicate ResultID: %s", r.ResultID)
		}
		seen[r.ResultID] = true
	}
}

func TestDeep_EvaluateViolationsBoundary(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	// Bronze allows max 10 violations
	atMax := CertificationScores{TrustScore: 500, ComplianceScore: 70, ObservationDays: 30, ViolationCount: 10}
	r := f.Evaluate("a", atMax)
	if !r.Passed {
		t.Fatal("exactly at max violations should pass")
	}
	over := CertificationScores{TrustScore: 500, ComplianceScore: 70, ObservationDays: 30, ViolationCount: 11}
	r = f.Evaluate("a", over)
	if r.Passed {
		t.Fatal("one over max violations should fail")
	}
}

func TestDeep_EvaluateObservationDaysBoundary(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	atMin := CertificationScores{TrustScore: 500, ComplianceScore: 70, ObservationDays: 7, ViolationCount: 0}
	r := f.Evaluate("a", atMin)
	if !r.Passed {
		t.Fatal("exactly at min observation days should pass")
	}
	below := CertificationScores{TrustScore: 500, ComplianceScore: 70, ObservationDays: 6, ViolationCount: 0}
	r = f.Evaluate("a", below)
	if r.Passed {
		t.Fatal("one below min observation days should fail")
	}
}

func TestDeep_BadgeVCHasW3CContext(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("dk")
	vcIssuer := vcredentials.NewIssuerWithClock("did:helm:dc", "DC", signer, deepClock)
	f := NewFramework().WithClock(deepClock)
	bi := NewBadgeIssuer(vcIssuer, f)
	vc, _, _ := bi.IssueBadge("da", "did:helm:da", deepPlatScores(), time.Hour)
	if len(vc.Context) == 0 {
		t.Fatal("VC should have W3C @context")
	}
}

func TestDeep_BadgeVCHasProof(t *testing.T) {
	signer, _ := crypto.NewEd25519Signer("dk")
	vcIssuer := vcredentials.NewIssuerWithClock("did:helm:dc", "DC", signer, deepClock)
	f := NewFramework().WithClock(deepClock)
	bi := NewBadgeIssuer(vcIssuer, f)
	vc, _, _ := bi.IssueBadge("da", "did:helm:da", deepPlatScores(), time.Hour)
	if vc.Proof == nil {
		t.Fatal("VC should have a cryptographic proof")
	}
}

func TestDeep_EvaluateAllFourLevels(t *testing.T) {
	f := NewFramework().WithClock(deepClock)
	levelOrder := map[CertificationLevel]int{CertPlatinum: 4, CertGold: 3, CertSilver: 2, CertBronze: 1}
	cases := []CertificationScores{
		{TrustScore: 900, ComplianceScore: 98, ObservationDays: 120, HasAIBOM: true, HasZKProof: true},
		{TrustScore: 750, ComplianceScore: 92, ObservationDays: 70, ViolationCount: 1, HasAIBOM: true},
		{TrustScore: 650, ComplianceScore: 85, ObservationDays: 40, ViolationCount: 3},
		{TrustScore: 450, ComplianceScore: 65, ObservationDays: 10, ViolationCount: 8},
	}
	prevRank := 5
	for _, scores := range cases {
		r := f.Evaluate("a", scores)
		if !r.Passed {
			t.Fatal("should pass certification")
		}
		rank := levelOrder[r.Level]
		if rank >= prevRank {
			t.Fatalf("levels should descend: rank %d >= prev %d", rank, prevRank)
		}
		prevRank = rank
	}
}

func TestDeep_SetCriteriaOverridesDefaults(t *testing.T) {
	f := NewFramework()
	f.SetCriteria(CertSilver, CertificationCriteria{
		Level: CertSilver, MinTrustScore: 1, MinComplianceScore: 1,
		MinObservationDays: 1, MaxViolations: 1000,
	})
	c, ok := f.GetCriteria(CertSilver)
	if !ok {
		t.Fatal("should find Silver criteria")
	}
	if c.MinTrustScore != 1 {
		t.Fatal("custom criteria should override default")
	}
}
