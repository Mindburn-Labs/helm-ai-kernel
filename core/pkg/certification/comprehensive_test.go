package certification

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

var compTime = time.Date(2026, 4, 12, 0, 0, 0, 0, time.UTC)

var compClock = func() time.Time { return compTime }

func platinumScores() CertificationScores {
	return CertificationScores{
		TrustScore: 900, ComplianceScore: 99, ObservationDays: 120,
		ViolationCount: 0, HasAIBOM: true, HasZKProof: true,
	}
}

func TestFrameworkEvaluatePlatinum(t *testing.T) {
	f := NewFramework().WithClock(compClock)
	r := f.Evaluate("agent-1", platinumScores())
	if !r.Passed || r.Level != CertPlatinum {
		t.Fatalf("expected PLATINUM pass, got level=%s passed=%v", r.Level, r.Passed)
	}
}

func TestFrameworkEvaluateGold(t *testing.T) {
	f := NewFramework().WithClock(compClock)
	scores := CertificationScores{
		TrustScore: 750, ComplianceScore: 92, ObservationDays: 70,
		ViolationCount: 1, HasAIBOM: true, HasZKProof: false,
	}
	r := f.Evaluate("agent-1", scores)
	if !r.Passed || r.Level != CertGold {
		t.Fatalf("expected GOLD, got level=%s passed=%v", r.Level, r.Passed)
	}
}

func TestFrameworkEvaluateSilver(t *testing.T) {
	f := NewFramework().WithClock(compClock)
	scores := CertificationScores{
		TrustScore: 650, ComplianceScore: 85, ObservationDays: 40,
		ViolationCount: 3, HasAIBOM: false,
	}
	r := f.Evaluate("agent-1", scores)
	if !r.Passed || r.Level != CertSilver {
		t.Fatalf("expected SILVER, got level=%s passed=%v", r.Level, r.Passed)
	}
}

func TestFrameworkEvaluateBronze(t *testing.T) {
	f := NewFramework().WithClock(compClock)
	scores := CertificationScores{
		TrustScore: 450, ComplianceScore: 65, ObservationDays: 10,
		ViolationCount: 8,
	}
	r := f.Evaluate("agent-1", scores)
	if !r.Passed || r.Level != CertBronze {
		t.Fatalf("expected BRONZE, got level=%s passed=%v", r.Level, r.Passed)
	}
}

func TestFrameworkEvaluateFailsBelowBronze(t *testing.T) {
	f := NewFramework().WithClock(compClock)
	scores := CertificationScores{TrustScore: 100, ComplianceScore: 20, ObservationDays: 1, ViolationCount: 50}
	r := f.Evaluate("agent-1", scores)
	if r.Passed {
		t.Fatal("expected failure below bronze")
	}
	if r.Reason == "" {
		t.Fatal("reason should explain why below bronze")
	}
}

func TestFrameworkSetCriteria(t *testing.T) {
	f := NewFramework()
	f.SetCriteria(CertBronze, CertificationCriteria{MinTrustScore: 100})
	c, ok := f.GetCriteria(CertBronze)
	if !ok || c.MinTrustScore != 100 {
		t.Fatalf("expected custom bronze criteria, got %v", c)
	}
}

func TestFrameworkGetCriteriaNotFound(t *testing.T) {
	f := NewFramework()
	_, ok := f.GetCriteria("DIAMOND")
	if ok {
		t.Fatal("DIAMOND should not exist")
	}
}

func TestFrameworkContentHashPopulated(t *testing.T) {
	f := NewFramework().WithClock(compClock)
	r := f.Evaluate("a1", platinumScores())
	if r.ContentHash == "" || r.ContentHash == "hash-error" {
		t.Fatalf("content hash should be populated, got %s", r.ContentHash)
	}
}

func TestFrameworkResultIDFormat(t *testing.T) {
	f := NewFramework().WithClock(compClock)
	r := f.Evaluate("myagent", platinumScores())
	if !strings.HasPrefix(r.ResultID, "cert-myagent-") {
		t.Fatalf("result ID format wrong: %s", r.ResultID)
	}
}

func TestCertifierCreateAndSign(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCertifier("signer-1", "release-manager", priv)
	att, err := c.CreateAttestation(
		ModuleIdentity{ModuleID: "mod-1", ArtifactHash: "abc", ManifestHash: "def"},
		BuildProvenance{BuilderID: "ci", Reproducible: true},
		CertificationResults{SchemaConformance: ConformanceResult{Passed: true}},
	)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := c.Sign(att); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(att.Signatures) != 1 || att.Signatures[0].SignerID != "signer-1" {
		t.Fatalf("signature not added correctly")
	}
	keys := map[string]ed25519.PublicKey{"signer-1": pub}
	if err := att.Verify(keys); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestAttestationVerifyRejectsTampered(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCertifier("signer-1", "admin", priv)
	att, _ := c.CreateAttestation(
		ModuleIdentity{ModuleID: "m", ArtifactHash: "a", ManifestHash: "b"},
		BuildProvenance{BuilderID: "ci"},
		CertificationResults{},
	)
	c.Sign(att)
	keys := map[string]ed25519.PublicKey{"signer-1": pub2} // wrong key
	if err := att.Verify(keys); err == nil {
		t.Fatal("expected verification failure with wrong key")
	}
}

func TestAttestationVerifyUnknownSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCertifier("signer-1", "admin", priv)
	att, _ := c.CreateAttestation(
		ModuleIdentity{ModuleID: "m", ArtifactHash: "a", ManifestHash: "b"},
		BuildProvenance{BuilderID: "ci"},
		CertificationResults{},
	)
	c.Sign(att)
	if err := att.Verify(map[string]ed25519.PublicKey{}); err == nil {
		t.Fatal("expected unknown signer error")
	}
}

func TestSignReportSuccess(t *testing.T) {
	report, err := SignReport("r-1", "abc123", []string{"L1", "L2"}, "k1", func(data []byte) ([]byte, error) {
		return []byte("sig"), nil
	})
	if err != nil || report == nil {
		t.Fatalf("sign report: err=%v", err)
	}
	if report.Standard != "HELM-STD-2026" || len(report.PassedSuites) != 2 {
		t.Fatalf("report fields wrong: standard=%s suites=%d", report.Standard, len(report.PassedSuites))
	}
	if len(report.Signature) == 0 {
		t.Fatal("signature should be populated")
	}
}

func TestCertLevelsDescendingOrder(t *testing.T) {
	expected := []CertificationLevel{CertPlatinum, CertGold, CertSilver, CertBronze}
	for i, l := range certLevelsDescending {
		if l != expected[i] {
			t.Fatalf("level %d: expected %s, got %s", i, expected[i], l)
		}
	}
}

func TestFrameworkEvaluateViolationCountExceedsMax(t *testing.T) {
	f := NewFramework().WithClock(compClock)
	scores := CertificationScores{
		TrustScore: 900, ComplianceScore: 99, ObservationDays: 120,
		ViolationCount: 1, HasAIBOM: true, HasZKProof: true,
	}
	r := f.Evaluate("agent-1", scores)
	// 1 violation disqualifies from PLATINUM (max 0), should get GOLD (max 2)
	if r.Level != CertGold {
		t.Fatalf("1 violation should yield GOLD, got %s", r.Level)
	}
}
