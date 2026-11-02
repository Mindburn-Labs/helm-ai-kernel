package trust

import (
	"crypto"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ─── 1: Registry Reduce DID register ─────────────────────────────

// ─── 2: Registry Reduce Key publish ──────────────────────────────

// ─── 3: Registry Reduce Key revoke ──────────────────────────────

// ─── 4: Registry Reduce Policy activate ──────────────────────────

// ─── 5: Registry Reduce Role grant ──────────────────────────────

// ─── 6: Registry Reduce Role revoke ─────────────────────────────

// ─── 7: Registry Reduce Tenant register ──────────────────────────

// ─── 8: Registry Reduce Tenant suspend ───────────────────────────

// ─── 9: Registry Reduce TrustScore update ────────────────────────

// ─── 10: Registry Reduce OrgTrust skipped (forward compat) ──────

// ─── 11: Registry point-in-time key active ───────────────────────

// ─── 12: Registry strict mode rejects unknown event type ─────────

// ─── 13: Registry non-strict mode skips unknown ──────────────────

// ─── 14: Registry out-of-order lamport rejected ──────────────────

// ─── 15: ComplianceMatrix add framework and control ──────────────

func TestExt2_ComplianceMatrixAddFrameworkControl(t *testing.T) {
	m := NewComplianceMatrix()
	m.AddFramework(&Framework{FrameworkID: "soc2", Name: "SOC 2"})
	err := m.AddControl(&Control{ControlID: "c1", FrameworkID: "soc2", Title: "Access Control"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Controls["c1"].Title != "Access Control" {
		t.Fatal("control should be added")
	}
}

func TestExt2_ComplianceMatrixHashChanges(t *testing.T) {
	m := NewComplianceMatrix()
	m.AddFramework(&Framework{FrameworkID: "fw1", Name: "Test"})
	h1 := m.Hash()
	m.AddControl(&Control{ControlID: "c1", FrameworkID: "fw1"})
	h2 := m.Hash()
	if h1 == h2 {
		t.Fatal("hash should change when control added")
	}
}

func TestExt2_PackScoringPerfect(t *testing.T) {
	score := ComputePackTrustScore(PackMetrics{
		AttestationCompleteness: 1.0,
		ReplayDeterminism:       1.0,
		InjectionResilience:     1.0,
		SLOAdherence:            1.0,
	})
	if score.PackScore != 1.0 {
		t.Fatalf("perfect metrics should give 1.0, got %f", score.PackScore)
	}
}

func TestExt2_PackScoringZero(t *testing.T) {
	score := ComputePackTrustScore(PackMetrics{})
	if score.PackScore != 0.0 {
		t.Fatalf("zero metrics should give 0.0, got %f", score.PackScore)
	}
}

func TestExt2_TUFClientRequiresURL(t *testing.T) {
	_, err := NewTUFClient(TUFClientConfig{RootKeys: []crypto.PublicKey{nil}})
	if err == nil || !strings.Contains(err.Error(), "remote URL") {
		t.Fatal("expected error for missing remote URL")
	}
}

func TestExt2_TUFClientRequiresRootKeys(t *testing.T) {
	_, err := NewTUFClient(TUFClientConfig{RemoteURL: "https://tuf.example.com"})
	if err == nil || !strings.Contains(err.Error(), "root key") {
		t.Fatal("expected error for missing root keys")
	}
}

func TestExt2_SLSAVerifierCorrectStatement(t *testing.T) {
	v := NewSLSAVerifier(&ProvenancePolicy{AllowedBuilders: []string{"github-actions"}})
	pred, _ := json.Marshal(SLSAProvenance{
		BuildDefinition: BuildDefinition{BuildType: "test"},
		RunDetails:      RunDetails{Builder: Builder{ID: "github-actions"}},
	})
	stmt := &InTotoStatement{
		Type: InTotoStatementType, PredicateType: SLSAProvenancePredicateType,
		Subject:   []Subject{{Name: "pack", Digest: map[string]string{"sha256": "abc"}}},
		Predicate: pred,
	}
	if err := v.VerifyAttestation(stmt); err != nil {
		t.Fatalf("valid statement should pass: %v", err)
	}
}

func TestExt2_SLSAVerifierRejectsUnknownBuilder(t *testing.T) {
	v := NewSLSAVerifier(&ProvenancePolicy{AllowedBuilders: []string{"github-actions"}})
	pred, _ := json.Marshal(SLSAProvenance{
		RunDetails: RunDetails{Builder: Builder{ID: "evil-builder"}},
	})
	stmt := &InTotoStatement{
		Type: InTotoStatementType, PredicateType: SLSAProvenancePredicateType,
		Predicate: pred,
	}
	if err := v.VerifyAttestation(stmt); err == nil {
		t.Fatal("unknown builder should be rejected")
	}
}

func TestExt2_SLSAVerifySubjectHashMatch(t *testing.T) {
	v := NewSLSAVerifier(nil)
	stmt := &InTotoStatement{
		Subject: []Subject{{Name: "pack", Digest: map[string]string{"sha256": "deadbeef"}}},
	}
	if err := v.VerifySubjectHash(stmt, "deadbeef"); err != nil {
		t.Fatalf("matching hash should pass: %v", err)
	}
}

func TestExt2_UpgradeRegistryRecordAndGet(t *testing.T) {
	r := NewUpgradeRegistry()
	receipt, err := r.RecordUpgrade("my-pack", "1.0.0", "2.0.0", "admin", CompatFull, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(receipt.ReceiptID)
	if err != nil || got.PackName != "my-pack" {
		t.Fatal("should retrieve recorded upgrade")
	}
}

func TestExt2_UpgradeBreakingNoSchemaCheck(t *testing.T) {
	r := NewUpgradeRegistry()
	_, err := r.RecordUpgrade("pack", "1.0", "2.0", "admin", CompatBreaking, false, false, false)
	if err == nil {
		t.Fatal("breaking upgrade without schema check should fail")
	}
}

// helper to avoid unused import warning
var _ = time.Now
