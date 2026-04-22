package evidence

import (
	"testing"
	"time"
)

func TestNewBuilder(t *testing.T) {
	b := NewBuilder("pack-001", "run-001")
	if b == nil {
		t.Fatal("expected non-nil builder")
	}

	pack := b.Build()
	if pack.PackID != "pack-001" {
		t.Errorf("expected pack ID pack-001, got %s", pack.PackID)
	}
	if pack.RunID != "run-001" {
		t.Errorf("expected run ID run-001, got %s", pack.RunID)
	}
}

func TestBuilderFluentAPI(t *testing.T) {
	pack := NewBuilder("pack-002", "run-002").
		AddSourceVersion("eu-eurlex", "v2024-01-15").
		AddSourceVersion("us-ofac-sdn", "2024-01-15T00:00:00Z").
		AddArtifactHash("sources/eu-eurlex/raw.json", "abc123").
		AddTrustCheck(TrustCheckResult{
			SourceID:  "eu-eurlex",
			CheckType: "tls",
			Passed:    true,
			Details:   "TLS 1.3 verified",
		}).
		AddNormalization(NormalizationEntry{
			Step:       1,
			SourceID:   "eu-eurlex",
			InputHash:  "aaa",
			OutputHash: "bbb",
			Profile:    "eurlex-v1",
		}).
		AddMapping(MappingDecision{
			SourceID:     "eu-eurlex",
			ObligationID: "OBL-EU-GDPR-001",
			Rationale:    "Direct legislative mandate",
			Confidence:   0.95,
		}).
		AddCompilerStep(CompilerTraceEntry{
			Step:      1,
			Phase:     "tier1_load",
			ControlID: "CLT-AC-001",
			Result:    "loaded",
		}).
		AddPolicyStep(PolicyTraceEntry{
			Step:      1,
			Rule:      "sanctions_block",
			Input:     "entity:acme-corp",
			Output:    "no_match",
			Timestamp: time.Now(),
		}).
		SetAction("ALLOW").
		Build()

	if len(pack.SourceVersions) != 2 {
		t.Errorf("expected 2 source versions, got %d", len(pack.SourceVersions))
	}
	if len(pack.ArtifactHashes) != 1 {
		t.Errorf("expected 1 artifact hash, got %d", len(pack.ArtifactHashes))
	}
	if len(pack.TrustChecks) != 1 {
		t.Errorf("expected 1 trust check, got %d", len(pack.TrustChecks))
	}
	if len(pack.NormalizationTrace) != 1 {
		t.Errorf("expected 1 normalization entry, got %d", len(pack.NormalizationTrace))
	}
	if len(pack.MappingDecisions) != 1 {
		t.Errorf("expected 1 mapping decision, got %d", len(pack.MappingDecisions))
	}
	if len(pack.CompilerTrace) != 1 {
		t.Errorf("expected 1 compiler trace, got %d", len(pack.CompilerTrace))
	}
	if len(pack.PolicyTrace) != 1 {
		t.Errorf("expected 1 policy trace, got %d", len(pack.PolicyTrace))
	}
	if pack.EnforcementAction != "ALLOW" {
		t.Errorf("expected action ALLOW, got %s", pack.EnforcementAction)
	}
}

func TestEvidencePackHashDeterminism(t *testing.T) {
	buildPack := func() *EvidencePack {
		return NewBuilder("pack-det", "run-det").
			AddSourceVersion("src-a", "v1").
			AddSourceVersion("src-b", "v2").
			AddArtifactHash("file1.json", "hash1").
			SetAction("BLOCK").
			Build()
	}

	pack1 := buildPack()
	pack2 := buildPack()

	// Force same timestamp for determinism test
	pack2.Timestamp = pack1.Timestamp

	h1 := pack1.Hash()
	h2 := pack2.Hash()

	if h1 != h2 {
		t.Errorf("hashes differ: %s vs %s", h1, h2)
	}
	if h1 == "" {
		t.Error("expected non-empty hash")
	}
}

func TestSanctionsScreeningReceipt(t *testing.T) {
	receipt := SanctionsScreeningReceipt{
		ReceiptID:      "ssr-001",
		Timestamp:      time.Now(),
		SubjectName:    "Acme Corp",
		SubjectID:      "entity-12345",
		ListVersions:   map[string]string{"OFAC-SDN": "2024-01-15", "EU-Sanctions": "2024-01-15"},
		MatchAlgorithm: "fuzzy_jaro_winkler",
		MatchScore:     0.0,
		MatchResult:    "NO_MATCH",
		EvidencePackID: "pack-001",
	}

	if receipt.MatchResult != "NO_MATCH" {
		t.Errorf("expected NO_MATCH, got %s", receipt.MatchResult)
	}
	if len(receipt.ListVersions) != 2 {
		t.Errorf("expected 2 list versions, got %d", len(receipt.ListVersions))
	}
}

func TestDataProtectionReceipt(t *testing.T) {
	receipt := DataProtectionReceipt{
		ReceiptID:        "dpr-001",
		Timestamp:        time.Now(),
		RequestType:      "DSAR",
		LawfulBasis:      "legitimate_interest",
		DataSubjectScope: "EU residents",
		ResponseDeadline: time.Now().Add(30 * 24 * time.Hour),
		SupervisoryAuth:  "FR-CNIL",
		EvidencePackID:   "pack-002",
	}

	if receipt.RequestType != "DSAR" {
		t.Errorf("expected DSAR, got %s", receipt.RequestType)
	}
}

func TestSupplyChainReceipt(t *testing.T) {
	receipt := SupplyChainReceipt{
		ReceiptID:        "scr-001",
		Timestamp:        time.Now(),
		SBOMHash:         "sha256:abc123",
		VulnSnapshotHash: "sha256:def456",
		CriticalVulns:    0,
		HighVulns:        2,
		KEVMatches:       0,
		ProvenanceChecks: map[string]bool{"artifact-1": true, "artifact-2": true},
		PolicyDecision:   "WARN",
		EvidencePackID:   "pack-003",
	}

	if receipt.PolicyDecision != "WARN" {
		t.Errorf("expected WARN, got %s", receipt.PolicyDecision)
	}
	if receipt.CriticalVulns != 0 {
		t.Errorf("expected 0 critical vulns, got %d", receipt.CriticalVulns)
	}
}

func TestIdentityTrustReceipt(t *testing.T) {
	receipt := IdentityTrustReceipt{
		ReceiptID:          "itr-001",
		Timestamp:          time.Now(),
		SignatureValid:     true,
		SignerIdentity:     "CN=HELM Signer, O=Peycheff",
		TrustAnchorID:      "eu-lotl-root",
		CertificateChain:   []string{"leaf-cert", "intermediate", "root"},
		QualifiedSignature: true,
		TimestampValid:     true,
		LTVStatus:          "VALID",
		EvidencePackID:     "pack-004",
	}

	if !receipt.QualifiedSignature {
		t.Error("expected qualified signature")
	}
	if len(receipt.CertificateChain) != 3 {
		t.Errorf("expected 3 certificates in chain, got %d", len(receipt.CertificateChain))
	}
}
