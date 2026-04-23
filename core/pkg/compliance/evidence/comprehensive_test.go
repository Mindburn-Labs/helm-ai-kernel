package evidence

import (
	"testing"
	"time"
)

func TestBuilder_Init(t *testing.T) {
	b := NewBuilder("pack-1", "run-1")
	pack := b.Build()
	if pack.PackID != "pack-1" || pack.RunID != "run-1" {
		t.Error("builder should set PackID and RunID")
	}
	if pack.Timestamp.IsZero() {
		t.Error("timestamp should be auto-set")
	}
}

func TestBuilder_SourceVersions(t *testing.T) {
	pack := NewBuilder("p", "r").
		AddSourceVersion("src-1", "v1.0").
		AddSourceVersion("src-2", "v2.0").
		Build()
	if pack.SourceVersions["src-1"] != "v1.0" {
		t.Error("expected source version v1.0")
	}
	if len(pack.SourceVersions) != 2 {
		t.Errorf("expected 2 source versions, got %d", len(pack.SourceVersions))
	}
}

func TestBuilder_ArtifactHashes(t *testing.T) {
	pack := NewBuilder("p", "r").
		AddArtifactHash("file.txt", "abc123").
		Build()
	if pack.ArtifactHashes["file.txt"] != "abc123" {
		t.Error("expected artifact hash 'abc123'")
	}
}

func TestBuilder_TrustChecks(t *testing.T) {
	pack := NewBuilder("p", "r").
		AddTrustCheck(TrustCheckResult{SourceID: "s1", CheckType: "signature", Passed: true}).
		AddTrustCheck(TrustCheckResult{SourceID: "s2", CheckType: "hash", Passed: false}).
		Build()
	if len(pack.TrustChecks) != 2 {
		t.Errorf("expected 2 trust checks, got %d", len(pack.TrustChecks))
	}
}

func TestBuilder_NormalizationTrace(t *testing.T) {
	pack := NewBuilder("p", "r").
		AddNormalization(NormalizationEntry{Step: 1, SourceID: "s1", Profile: "gdpr"}).
		Build()
	if len(pack.NormalizationTrace) != 1 {
		t.Error("expected 1 normalization entry")
	}
	if pack.NormalizationTrace[0].Profile != "gdpr" {
		t.Error("expected profile 'gdpr'")
	}
}

func TestBuilder_MappingDecisions(t *testing.T) {
	pack := NewBuilder("p", "r").
		AddMapping(MappingDecision{
			SourceID: "s1", ObligationID: "obl-1", Confidence: 0.95,
		}).
		Build()
	if len(pack.MappingDecisions) != 1 {
		t.Error("expected 1 mapping decision")
	}
	if pack.MappingDecisions[0].Confidence != 0.95 {
		t.Error("expected confidence 0.95")
	}
}

func TestBuilder_CompilerTrace(t *testing.T) {
	pack := NewBuilder("p", "r").
		AddCompilerStep(CompilerTraceEntry{Step: 1, Phase: "tier1_load", Result: "ok"}).
		Build()
	if len(pack.CompilerTrace) != 1 {
		t.Error("expected 1 compiler trace entry")
	}
}

func TestBuilder_PolicyTrace(t *testing.T) {
	pack := NewBuilder("p", "r").
		AddPolicyStep(PolicyTraceEntry{
			Step: 1, Rule: "egress_check", Input: "api.example.com",
			Output: "ALLOW", Timestamp: time.Now(),
		}).
		Build()
	if len(pack.PolicyTrace) != 1 {
		t.Error("expected 1 policy trace entry")
	}
}

func TestBuilder_EnforcementAction(t *testing.T) {
	pack := NewBuilder("p", "r").SetAction("BLOCK").Build()
	if pack.EnforcementAction != "BLOCK" {
		t.Errorf("expected action 'BLOCK', got %q", pack.EnforcementAction)
	}
}

func TestBuilder_ChainingReturnsSameBuilder(t *testing.T) {
	b := NewBuilder("p", "r")
	b2 := b.AddSourceVersion("s", "v").AddArtifactHash("f", "h").SetAction("ALLOW")
	if b != b2 {
		t.Error("builder methods should return the same builder for chaining")
	}
}

func TestEvidencePack_HashIsDeterministic(t *testing.T) {
	pack := NewBuilder("p", "r").
		AddSourceVersion("s1", "v1").
		AddArtifactHash("f1", "h1").
		SetAction("ALLOW").
		Build()
	h1 := pack.Hash()
	h2 := pack.Hash()
	if h1 != h2 {
		t.Error("hash should be deterministic")
	}
	if h1 == "" {
		t.Error("hash should not be empty")
	}
}

func TestEvidencePack_DifferentPacksDifferentHash(t *testing.T) {
	p1 := NewBuilder("p1", "r1").SetAction("ALLOW").Build()
	p2 := NewBuilder("p2", "r2").SetAction("BLOCK").Build()
	if p1.Hash() == p2.Hash() {
		t.Error("different packs should produce different hashes")
	}
}

func TestSanctionsScreeningReceipt_FieldValues(t *testing.T) {
	r := SanctionsScreeningReceipt{
		ReceiptID: "sr-1", SubjectName: "John Doe",
		MatchResult: "NO_MATCH", MatchScore: 0.1,
	}
	if r.MatchResult != "NO_MATCH" {
		t.Error("expected NO_MATCH")
	}
}

func TestDataProtectionReceipt_FieldValues(t *testing.T) {
	now := time.Now()
	r := DataProtectionReceipt{
		ReceiptID: "dp-1", RequestType: "DSAR",
		ResponseDeadline: now.Add(30 * 24 * time.Hour),
	}
	if r.RequestType != "DSAR" {
		t.Error("expected DSAR request type")
	}
}

func TestSupplyChainReceipt_FieldValues(t *testing.T) {
	r := SupplyChainReceipt{
		ReceiptID: "sc-1", CriticalVulns: 0, HighVulns: 2,
		PolicyDecision: "WARN",
	}
	if r.PolicyDecision != "WARN" {
		t.Error("expected WARN policy decision")
	}
}
