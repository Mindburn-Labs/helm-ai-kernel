package certification

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"
)

func TestFinal_CertLevelConstants(t *testing.T) {
	levels := []CertificationLevel{CertBronze, CertSilver, CertGold, CertPlatinum}
	if len(levels) != 4 {
		t.Fatal("expected 4 levels")
	}
}

func TestFinal_CertLevelsDescendingOrder(t *testing.T) {
	if certLevelsDescending[0] != CertPlatinum || certLevelsDescending[3] != CertBronze {
		t.Fatal("wrong order")
	}
}

func TestFinal_CertificationCriteriaJSONRoundTrip(t *testing.T) {
	c := CertificationCriteria{Level: CertGold, MinTrustScore: 700, RequiresAIBOM: true}
	data, _ := json.Marshal(c)
	var got CertificationCriteria
	json.Unmarshal(data, &got)
	if got.Level != CertGold || got.MinTrustScore != 700 {
		t.Fatal("round-trip mismatch")
	}
}

func TestFinal_CertificationScoresJSONRoundTrip(t *testing.T) {
	s := CertificationScores{TrustScore: 850, ComplianceScore: 98, HasAIBOM: true}
	data, _ := json.Marshal(s)
	var got CertificationScores
	json.Unmarshal(data, &got)
	if got.TrustScore != 850 || !got.HasAIBOM {
		t.Fatal("round-trip")
	}
}

func TestFinal_CertificationResultJSONRoundTrip(t *testing.T) {
	r := CertificationResult{ResultID: "r1", AgentID: "a1", Level: CertPlatinum, Passed: true}
	data, _ := json.Marshal(r)
	var got CertificationResult
	json.Unmarshal(data, &got)
	if got.Level != CertPlatinum || !got.Passed {
		t.Fatal("result round-trip")
	}
}

func TestFinal_NewFramework(t *testing.T) {
	f := NewFramework()
	if f == nil {
		t.Fatal("nil framework")
	}
}

func TestFinal_DefaultBronzeCriteria(t *testing.T) {
	f := NewFramework()
	c, ok := f.GetCriteria(CertBronze)
	if !ok || c.MinTrustScore != 400 {
		t.Fatal("bronze criteria")
	}
}

func TestFinal_DefaultPlatinumCriteria(t *testing.T) {
	f := NewFramework()
	c, _ := f.GetCriteria(CertPlatinum)
	if !c.RequiresZKProof || !c.RequiresAIBOM {
		t.Fatal("platinum should require ZK and AIBOM")
	}
}

func TestFinal_SetCriteriaOverrides(t *testing.T) {
	f := NewFramework()
	f.SetCriteria(CertBronze, CertificationCriteria{MinTrustScore: 100})
	c, _ := f.GetCriteria(CertBronze)
	if c.MinTrustScore != 100 {
		t.Fatal("override not applied")
	}
}

func TestFinal_EvaluatePlatinumPass(t *testing.T) {
	f := NewFramework()
	scores := CertificationScores{TrustScore: 900, ComplianceScore: 99, ObservationDays: 100, ViolationCount: 0, HasAIBOM: true, HasZKProof: true}
	result := f.Evaluate("agent-1", scores)
	if !result.Passed || result.Level != CertPlatinum {
		t.Fatalf("expected PLATINUM pass, got %s passed=%v", result.Level, result.Passed)
	}
}

func TestFinal_EvaluateBronzePass(t *testing.T) {
	f := NewFramework()
	scores := CertificationScores{TrustScore: 450, ComplianceScore: 65, ObservationDays: 10, ViolationCount: 5}
	result := f.Evaluate("agent-1", scores)
	if !result.Passed || result.Level != CertBronze {
		t.Fatalf("expected BRONZE pass, got %s passed=%v", result.Level, result.Passed)
	}
}

func TestFinal_EvaluateFailsBelowBronze(t *testing.T) {
	f := NewFramework()
	scores := CertificationScores{TrustScore: 100, ComplianceScore: 20, ObservationDays: 1}
	result := f.Evaluate("agent-1", scores)
	if result.Passed {
		t.Fatal("should not pass")
	}
	if result.Reason == "" {
		t.Fatal("reason should explain failure")
	}
}

func TestFinal_EvaluateContentHashSet(t *testing.T) {
	f := NewFramework()
	scores := CertificationScores{TrustScore: 500, ComplianceScore: 70, ObservationDays: 10, ViolationCount: 3}
	result := f.Evaluate("agent-1", scores)
	if result.ContentHash == "" {
		t.Fatal("content hash should be set")
	}
}

func TestFinal_EvaluateDeterministic(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	f1 := NewFramework().WithClock(func() time.Time { return fixed })
	f2 := NewFramework().WithClock(func() time.Time { return fixed })
	scores := CertificationScores{TrustScore: 500, ComplianceScore: 70, ObservationDays: 10}
	r1 := f1.Evaluate("a", scores)
	r2 := f2.Evaluate("a", scores)
	if r1.ContentHash != r2.ContentHash {
		t.Fatal("hashes should match")
	}
}

func TestFinal_ModuleAttestationJSONRoundTrip(t *testing.T) {
	ma := ModuleAttestation{AttestationID: "att-1", Version: "1.0.0"}
	data, _ := json.Marshal(ma)
	var got ModuleAttestation
	json.Unmarshal(data, &got)
	if got.AttestationID != "att-1" {
		t.Fatal("attestation round-trip")
	}
}

func TestFinal_ModuleIdentityJSONRoundTrip(t *testing.T) {
	mi := ModuleIdentity{ModuleID: "m1", Name: "test", ArtifactHash: "h1"}
	data, _ := json.Marshal(mi)
	var got ModuleIdentity
	json.Unmarshal(data, &got)
	if got.ModuleID != "m1" {
		t.Fatal("identity round-trip")
	}
}

func TestFinal_BuildProvenanceJSONRoundTrip(t *testing.T) {
	bp := BuildProvenance{BuilderID: "b1", Reproducible: true}
	data, _ := json.Marshal(bp)
	var got BuildProvenance
	json.Unmarshal(data, &got)
	if got.BuilderID != "b1" || !got.Reproducible {
		t.Fatal("provenance round-trip")
	}
}

func TestFinal_NewCertifier(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCertifier("signer-1", "admin", priv)
	if c == nil {
		t.Fatal("nil certifier")
	}
}

func TestFinal_CreateAttestation(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCertifier("signer-1", "admin", priv)
	att, err := c.CreateAttestation(
		ModuleIdentity{ModuleID: "m1", ArtifactHash: "h1", ManifestHash: "mh1"},
		BuildProvenance{BuilderID: "b1"},
		CertificationResults{},
	)
	if err != nil || att == nil {
		t.Fatal("create failed")
	}
}

func TestFinal_SignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCertifier("signer-1", "admin", priv)
	att, _ := c.CreateAttestation(
		ModuleIdentity{ModuleID: "m1", ArtifactHash: "h1", ManifestHash: "mh1"},
		BuildProvenance{BuilderID: "b1"},
		CertificationResults{},
	)
	if err := c.Sign(att); err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{"signer-1": pub}
	if err := att.Verify(keys); err != nil {
		t.Fatal(err)
	}
}

func TestFinal_VerifyUnknownSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := NewCertifier("signer-1", "admin", priv)
	att, _ := c.CreateAttestation(
		ModuleIdentity{ModuleID: "m1", ArtifactHash: "h1", ManifestHash: "mh1"},
		BuildProvenance{BuilderID: "b1"},
		CertificationResults{},
	)
	c.Sign(att)
	err := att.Verify(map[string]ed25519.PublicKey{})
	if err == nil {
		t.Fatal("should fail with unknown signer")
	}
}

func TestFinal_ConformanceReportJSONRoundTrip(t *testing.T) {
	cr := ConformanceReport{ReportID: "r1", GitRevision: "abc123", Platform: "helm-core-go"}
	data, _ := json.Marshal(cr)
	var got ConformanceReport
	json.Unmarshal(data, &got)
	if got.ReportID != "r1" || got.Platform != "helm-core-go" {
		t.Fatal("report round-trip")
	}
}

func TestFinal_SignReportSuccess(t *testing.T) {
	signer := func(data []byte) ([]byte, error) { return []byte("sig"), nil }
	report, err := SignReport("r1", "abc123", []string{"suite1"}, "key-1", signer)
	if err != nil || report == nil {
		t.Fatal("sign report failed")
	}
	if len(report.Signature) == 0 {
		t.Fatal("signature not set")
	}
}

func TestFinal_SignReportStandard(t *testing.T) {
	signer := func(data []byte) ([]byte, error) { return []byte("sig"), nil }
	report, _ := SignReport("r1", "abc123", []string{"suite1"}, "key-1", signer)
	if report.Standard != "HELM-STD-2026" {
		t.Fatalf("unexpected standard: %s", report.Standard)
	}
}

func TestFinal_AttestationSignatureJSONRoundTrip(t *testing.T) {
	as := AttestationSignature{SignerID: "s1", Algorithm: "ed25519", Signature: "sig123"}
	data, _ := json.Marshal(as)
	var got AttestationSignature
	json.Unmarshal(data, &got)
	if got.SignerID != "s1" || got.Algorithm != "ed25519" {
		t.Fatal("sig round-trip")
	}
}

func TestFinal_AttestationValidityJSONRoundTrip(t *testing.T) {
	av := AttestationValidity{NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour)}
	data, _ := json.Marshal(av)
	var got AttestationValidity
	json.Unmarshal(data, &got)
	if got.NotBefore.IsZero() {
		t.Fatal("validity round-trip")
	}
}

func TestFinal_ConformanceResultJSONRoundTrip(t *testing.T) {
	cr := ConformanceResult{Passed: true, SchemasValidated: []string{"s1", "s2"}}
	data, _ := json.Marshal(cr)
	var got ConformanceResult
	json.Unmarshal(data, &got)
	if !got.Passed || len(got.SchemasValidated) != 2 {
		t.Fatal("conformance round-trip")
	}
}

func TestFinal_DeterminismTestResultJSONRoundTrip(t *testing.T) {
	dtr := DeterminismTestResult{Passed: true, TestCount: 100}
	data, _ := json.Marshal(dtr)
	var got DeterminismTestResult
	json.Unmarshal(data, &got)
	if got.TestCount != 100 {
		t.Fatal("determinism round-trip")
	}
}

func TestFinal_PermissionsDeclJSONRoundTrip(t *testing.T) {
	pd := PermissionsDecl{EffectTypes: []string{"DATA_WRITE"}, RequiredCapabilities: []string{"admin"}}
	data, _ := json.Marshal(pd)
	var got PermissionsDecl
	json.Unmarshal(data, &got)
	if len(got.EffectTypes) != 1 {
		t.Fatal("permissions round-trip")
	}
}
