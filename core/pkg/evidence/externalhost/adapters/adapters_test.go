package adapters

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence/externalhost"
)

const (
	// Issuer public keys from testdata synthetic vectors.
	signetIssuerKeyHex = "8d312fa3abb0100e320bd8cdf1c608e5226ca8e23db5f0af177542043db765b0"
	agtIssuerKeyHex    = "935738043db9209ce367587eb258e8f61a2ba733703b6dbb21bb7fcc30536f70"
)

func testdataFile(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read testdata %s: %v", name, err)
	}
	return data
}

// ─── Signet tests ────────────────────────────────────────────────────────────

func TestSignetToExternalReceiptChain_Verifies(t *testing.T) {
	raw := testdataFile(t, "signet_v1_synthetic.json")

	chain, err := SignetToExternalReceiptChain(raw)
	if err != nil {
		t.Fatalf("SignetToExternalReceiptChain: %v", err)
	}

	if chain.SourceVendor != "signet" {
		t.Errorf("SourceVendor=%q, want signet", chain.SourceVendor)
	}
	if chain.SourceProfile != "signet-v4" {
		t.Errorf("SourceProfile=%q, want signet-v4", chain.SourceProfile)
	}
	if len(chain.Receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(chain.Receipts))
	}
	if len(chain.PublicKeys) == 0 {
		t.Fatal("expected public keys in chain")
	}
	if chain.PublicKeys[0].PublicKeyHex != signetIssuerKeyHex {
		t.Errorf("PublicKeyHex=%q, want %q", chain.PublicKeys[0].PublicKeyHex, signetIssuerKeyHex)
	}

	for i, r := range chain.Receipts {
		if r.EventKind != contracts.EventKindActionEffect {
			t.Errorf("receipt[%d].EventKind=%q, want %q", i, r.EventKind, contracts.EventKindActionEffect)
		}
		if r.ActionEvent == nil {
			t.Errorf("receipt[%d].ActionEvent is nil", i)
		}
		if r.SignedPayloadB64 == "" {
			t.Errorf("receipt[%d].SignedPayloadB64 is empty", i)
		}
		if r.ReceiptHash == "" {
			t.Errorf("receipt[%d].ReceiptHash is empty", i)
		}
	}

	ae0 := chain.Receipts[0].ActionEvent
	if ae0.ToolName != "github_create_issue" {
		t.Errorf("receipt[0] ToolName=%q, want github_create_issue", ae0.ToolName)
	}
	if ae0.Decision != "allow" {
		t.Errorf("receipt[0] Decision=%q, want allow", ae0.Decision)
	}

	if chain.Receipts[1].PrevReceiptHash == "" {
		t.Error("receipt[1].PrevReceiptHash is empty — hash chain broken")
	}
	if chain.Receipts[1].PrevReceiptHash != chain.Receipts[0].ReceiptHash {
		t.Errorf("receipt[1].PrevReceiptHash=%q, want receipt[0].ReceiptHash=%q",
			chain.Receipts[1].PrevReceiptHash, chain.Receipts[0].ReceiptHash)
	}

	report, err := externalhost.VerifyChain(chain, externalhost.VerifyOptions{
		RequireKey:   true,
		PublicKeyHex: signetIssuerKeyHex,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Verified {
		t.Errorf("Signet chain did not verify; checks: %+v", report.Checks)
	}
}

// TestSignetToExternalReceiptChain_BindingCheckCatchesTamper tests that
// signetBindingCheck rejects an ActionEvent that disagrees with the signed bytes.
// This exercises the adapter-time binding check independently of signature
// verification (which covers post-conversion tampering).
func TestSignetToExternalReceiptChain_BindingCheckCatchesTamper(t *testing.T) {
	raw := testdataFile(t, "signet_v1_synthetic.json")

	chain, err := SignetToExternalReceiptChain(raw)
	if err != nil {
		t.Fatalf("SignetToExternalReceiptChain: %v", err)
	}

	// Decode the SignedPayloadB64 that the adapter stored.
	signedBytes, err := base64.StdEncoding.DecodeString(chain.Receipts[0].SignedPayloadB64)
	if err != nil {
		t.Fatalf("decode SignedPayloadB64: %v", err)
	}

	// Build an ActionEvent with a wrong tool — must be rejected.
	badAE := &contracts.ActionEffectEvent{
		ToolName:   "injected_tool",
		TargetRef:  chain.Receipts[0].ActionEvent.TargetRef,
		ParamsHash: chain.Receipts[0].ActionEvent.ParamsHash,
	}
	if err := signetBindingCheck(signedBytes, badAE); err == nil {
		t.Fatal("expected signetBindingCheck to reject mismatched tool, got nil")
	} else {
		t.Logf("binding check correctly rejected mismatch: %v", err)
	}
}

// TestSignetToExternalReceiptChain_TamperAfterConversionFails verifies that
// tampering an ActionEvent field after conversion causes VerifyChain to fail.
func TestSignetToExternalReceiptChain_TamperAfterConversionFails(t *testing.T) {
	raw := testdataFile(t, "signet_v1_synthetic.json")

	chain, err := SignetToExternalReceiptChain(raw)
	if err != nil {
		t.Fatalf("SignetToExternalReceiptChain: %v", err)
	}

	// Tamper ActionEvent after conversion.
	chain.Receipts[0].ActionEvent.ToolName = "tampered_tool_post"

	report, err := externalhost.VerifyChain(chain, externalhost.VerifyOptions{
		RequireKey:   true,
		PublicKeyHex: signetIssuerKeyHex,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Verified {
		t.Fatal("tampered chain should not verify")
	}
	// receipt_hash changes when ActionEvent is tampered (ActionEvent is part of
	// the canonicalized receipt used to compute receipt_hash).
	assertFailedCheck(t, report, "external_host:receipt_hash")
}

func TestSignetToExternalReceiptChain_EmptyInput(t *testing.T) {
	_, err := SignetToExternalReceiptChain([]byte(`{"audit_records":[]}`))
	if err == nil {
		t.Fatal("expected error for empty audit_records")
	}
}

// ─── AGT tests ───────────────────────────────────────────────────────────────

func TestAGTToExternalReceiptChain_Verifies(t *testing.T) {
	raw := testdataFile(t, "agt_cedar_v1_synthetic.json")

	chain, err := AGTToExternalReceiptChain(raw)
	if err != nil {
		t.Fatalf("AGTToExternalReceiptChain: %v", err)
	}

	if chain.SourceVendor != "microsoft-agt" {
		t.Errorf("SourceVendor=%q, want microsoft-agt", chain.SourceVendor)
	}
	if chain.SourceProfile != "agt-cedar-v1" {
		t.Errorf("SourceProfile=%q, want agt-cedar-v1", chain.SourceProfile)
	}
	if len(chain.Receipts) != 2 {
		t.Fatalf("expected 2 receipts, got %d", len(chain.Receipts))
	}
	if len(chain.PublicKeys) == 0 {
		t.Fatal("expected public keys in chain")
	}
	if chain.PublicKeys[0].PublicKeyHex != agtIssuerKeyHex {
		t.Errorf("PublicKeyHex=%q, want %q", chain.PublicKeys[0].PublicKeyHex, agtIssuerKeyHex)
	}

	for i, r := range chain.Receipts {
		if r.EventKind != contracts.EventKindActionEffect {
			t.Errorf("receipt[%d].EventKind=%q, want %q", i, r.EventKind, contracts.EventKindActionEffect)
		}
		if r.ActionEvent == nil {
			t.Errorf("receipt[%d].ActionEvent is nil", i)
		}
		if r.SignedPayloadB64 == "" {
			t.Errorf("receipt[%d].SignedPayloadB64 is empty", i)
		}
		if r.ReceiptHash == "" {
			t.Errorf("receipt[%d].ReceiptHash is empty", i)
		}
	}

	r0 := chain.Receipts[0]
	if r0.Metadata["cedar_policy_id"] != "policy-github-tools-v1" {
		t.Errorf("receipt[0] Metadata[cedar_policy_id]=%q, want policy-github-tools-v1", r0.Metadata["cedar_policy_id"])
	}
	if r0.VerifierProfile == "" {
		t.Error("receipt[0].VerifierProfile is empty — cedar_policy_id hint missing")
	}

	ae0 := chain.Receipts[0].ActionEvent
	if ae0.ToolName != "github_create_issue" {
		t.Errorf("receipt[0] ToolName=%q, want github_create_issue", ae0.ToolName)
	}
	if ae0.Decision != "allow" {
		t.Errorf("receipt[0] Decision=%q, want allow", ae0.Decision)
	}
	if ae0.TargetRef != "did:web:agent.mindburn-labs.com:test-agent-001" {
		t.Errorf("receipt[0] TargetRef=%q, want agent DID", ae0.TargetRef)
	}

	if chain.Receipts[1].PrevReceiptHash == "" {
		t.Error("receipt[1].PrevReceiptHash is empty — hash chain broken")
	}
	if chain.Receipts[1].PrevReceiptHash != chain.Receipts[0].ReceiptHash {
		t.Errorf("receipt[1].PrevReceiptHash=%q, want receipt[0].ReceiptHash=%q",
			chain.Receipts[1].PrevReceiptHash, chain.Receipts[0].ReceiptHash)
	}

	report, err := externalhost.VerifyChain(chain, externalhost.VerifyOptions{
		RequireKey:   true,
		PublicKeyHex: agtIssuerKeyHex,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !report.Verified {
		t.Errorf("AGT chain did not verify; checks: %+v", report.Checks)
	}
}

// TestAGTToExternalReceiptChain_BindingCheckCatchesTamper verifies that
// agtBindingCheck rejects a payload that disagrees with the ActionEvent fields.
func TestAGTToExternalReceiptChain_BindingCheckCatchesTamper(t *testing.T) {
	raw := testdataFile(t, "agt_cedar_v1_synthetic.json")

	var file agtChainFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Tamper tool_name — the payload_hash will mismatch our reconstruction,
	// which is an earlier guard than the binding check. Both are verified:
	// the adapter rejects at reconstruction time (payload_hash mismatch acts
	// as the binding check sentinel here since the tampered tool changes the
	// canonical payload).
	file.Receipts[0].ToolName = "injected_tool"
	tampered, err := json.Marshal(file)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}

	_, err = AGTToExternalReceiptChain(tampered)
	if err == nil {
		t.Fatal("expected error for tampered tool_name, got nil")
	}
	t.Logf("correctly rejected tampered receipt: %v", err)
}

// TestAGTToExternalReceiptChain_BindingCheckDirectly tests agtBindingCheck by
// passing a signed payload that disagrees with a constructed ActionEvent.
func TestAGTToExternalReceiptChain_BindingCheckDirectly(t *testing.T) {
	raw := testdataFile(t, "agt_cedar_v1_synthetic.json")

	chain, err := AGTToExternalReceiptChain(raw)
	if err != nil {
		t.Fatalf("AGTToExternalReceiptChain: %v", err)
	}

	signedBytes, err := base64.StdEncoding.DecodeString(chain.Receipts[0].SignedPayloadB64)
	if err != nil {
		t.Fatalf("decode SignedPayloadB64: %v", err)
	}

	// ActionEvent with wrong tool name — binding check must reject.
	badAE := &contracts.ActionEffectEvent{
		ToolName: "injected_tool",
	}
	agentDID := "did:web:agent.mindburn-labs.com:test-agent-001"
	argsHash := "b878192252cbdcc6b3b42c0c8e75e3c3db0b5a2b8e3f4a4d5e6f7a8b9c0d1e2f"
	if err := agtBindingCheck(signedBytes, badAE, agentDID, argsHash); err == nil {
		t.Fatal("expected agtBindingCheck to reject mismatched tool_name, got nil")
	} else {
		t.Logf("binding check correctly rejected mismatch: %v", err)
	}
}

// TestAGTToExternalReceiptChain_TamperAfterConversionFails verifies that
// tampering an ActionEvent field after conversion causes VerifyChain to fail.
func TestAGTToExternalReceiptChain_TamperAfterConversionFails(t *testing.T) {
	raw := testdataFile(t, "agt_cedar_v1_synthetic.json")

	chain, err := AGTToExternalReceiptChain(raw)
	if err != nil {
		t.Fatalf("AGTToExternalReceiptChain: %v", err)
	}

	// Tamper ActionEvent after conversion — receipt_hash must fail.
	chain.Receipts[0].ActionEvent.ToolName = "tampered_post"

	report, err := externalhost.VerifyChain(chain, externalhost.VerifyOptions{
		RequireKey:   true,
		PublicKeyHex: agtIssuerKeyHex,
	})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if report.Verified {
		t.Fatal("tampered chain should not verify")
	}
	assertFailedCheck(t, report, "external_host:receipt_hash")
}

func TestAGTToExternalReceiptChain_EmptyInput(t *testing.T) {
	_, err := AGTToExternalReceiptChain([]byte(`{"receipts":[]}`))
	if err == nil {
		t.Fatal("expected error for empty receipts")
	}
}

// ─── Helper ──────────────────────────────────────────────────────────────────

func assertFailedCheck(t *testing.T, report *externalhost.VerificationReport, name string) {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name && !check.Pass {
			return
		}
	}
	t.Fatalf("missing failed check %q in %+v", name, report.Checks)
}

// TestSignetToExternalReceiptChain_BrokenChainFails proves a deleted/reordered/
// spliced Signet audit export is rejected at import: corrupting record[1].prev_hash
// breaks the vendor prev_hash -> record_hash chain.
func TestSignetToExternalReceiptChain_BrokenChainFails(t *testing.T) {
	raw := testdataFile(t, "signet_v1_synthetic.json")
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	recs, ok := m["audit_records"].([]interface{})
	if !ok || len(recs) < 2 {
		t.Fatalf("expected >=2 audit_records in synthetic vector, got %v", m["audit_records"])
	}
	recs[1].(map[string]interface{})["prev_hash"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0"
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignetToExternalReceiptChain(tampered); err == nil {
		t.Fatal("expected error for broken Signet prev_hash chain, got nil")
	}
}

// TestAGTToExternalReceiptChain_BrokenChainFails proves a broken AGT parent chain
// is rejected: corrupting receipt[1].parent_receipt_hash breaks contiguity.
func TestAGTToExternalReceiptChain_BrokenChainFails(t *testing.T) {
	raw := testdataFile(t, "agt_cedar_v1_synthetic.json")
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	recs, ok := m["receipts"].([]interface{})
	if !ok || len(recs) < 2 {
		t.Fatalf("expected >=2 receipts in synthetic vector, got %v", m["receipts"])
	}
	recs[1].(map[string]interface{})["parent_receipt_hash"] = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0"
	tampered, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AGTToExternalReceiptChain(tampered); err == nil {
		t.Fatal("expected error for broken AGT parent chain, got nil")
	}
}
