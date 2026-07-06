package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

// quantum_posture: verifier fixtures use classical Ed25519 signatures to
// exercise trust wiring; these tests do not claim post-quantum resistance.
// createValidBundleFixture creates a minimal valid evidence bundle directory
// with all required structural elements for the hardened verifier:
// manifest.json, 00_INDEX.json, proofgraph.json, receipts/ with a receipt.
func createValidBundleFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// manifest.json
	writeJSON(t, filepath.Join(dir, "manifest.json"), map[string]any{
		"session_id":  "test-session-001",
		"version":     "1.0.0",
		"exported_at": "2026-01-01T00:00:00Z",
		"file_hashes": map[string]string{},
	})

	// 00_INDEX.json
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{
		"version": "1.0.0",
		"gates":   []string{"G0", "G1"},
	})

	// proofgraph.json (required for chain_integrity)
	writeJSON(t, filepath.Join(dir, "proofgraph.json"), map[string]any{
		"version": "1.0.0",
		"nodes":   []any{},
		"edges":   []any{},
	})

	// receipts/ directory with a receipt containing decision_hash
	receiptsDir := filepath.Join(dir, "receipts")
	if err := os.MkdirAll(receiptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(receiptsDir, "receipt-001.json"), map[string]any{
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"status":        "APPLIED",
		"lamport_clock": 1,
	})

	sealVerifierFixture(t, dir, "test-session-001")
	return dir
}

func createValidCanonicalBundleFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{
		"version": "1.0.0",
		"entries": []any{},
	})
	writeJSON(t, filepath.Join(dir, "01_SCORE.json"), map[string]any{
		"pass": true,
	})
	for _, subdir := range []string{
		"02_PROOFGRAPH",
		"03_TELEMETRY",
		"04_EXPORTS",
		"05_DIFFS",
		"06_LOGS",
		"07_ATTESTATIONS",
		"08_TAPES",
		"09_SCHEMAS",
		"12_REPORTS",
	} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	if err := os.MkdirAll(receiptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(receiptsDir, "receipt-001.json"), map[string]any{
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"status":        "APPLIED",
		"lamport_clock": 1,
	})

	sealVerifierFixture(t, dir, "canonical-test")
	return dir
}

func sealVerifierFixture(t *testing.T, dir, packID string) {
	t.Helper()
	writeSealFixtureIndex(t, dir)
	if _, err := evidencepkg.SealEvidencePack(context.Background(), dir, evidencepkg.SealEvidencePackOptions{
		PackID:  packID,
		DataDir: t.TempDir(),
	}); err != nil {
		t.Fatalf("seal fixture: %v", err)
	}
}

func writeSealFixtureIndex(t *testing.T, dir string) {
	t.Helper()
	type entry struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	entries := []entry{}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		switch rel {
		case "00_INDEX.json", evidencepkg.EvidencePackSealPath:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		entries = append(entries, entry{Path: rel, SHA256: sha256Hex(data)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{
		"version": "1.0.0",
		"entries": entries,
	})
}

func TestVerifyBundle_Valid(t *testing.T) {
	dir := createValidBundleFixture(t)

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Verified {
		t.Errorf("expected PASS, got FAIL: %s", report.Summary)
		for _, c := range report.Checks {
			if !c.Pass {
				t.Logf("  FAIL: %s — %s", c.Name, c.Reason)
			}
		}
	}
	if report.VerifierVer != VerifierVersion {
		t.Errorf("expected version %s, got %s", VerifierVersion, report.VerifierVer)
	}
}

func TestVerifyBundle_CanonicalProofGraphReceipts(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Verified {
		t.Errorf("expected PASS, got FAIL: %s", report.Summary)
		for _, c := range report.Checks {
			if !c.Pass {
				t.Logf("  FAIL: %s — %s", c.Name, c.Reason)
			}
		}
	}
}

func TestVerifyBundle_RequiresEvidencePackSeal(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{
		"version": "1.0.0",
		"entries": []any{},
	})
	writeJSON(t, filepath.Join(dir, "01_SCORE.json"), map[string]any{"pass": true})
	for _, subdir := range []string{"02_PROOFGRAPH", "03_TELEMETRY", "04_EXPORTS", "05_DIFFS", "06_LOGS", "07_ATTESTATIONS", "08_TAPES", "09_SCHEMAS", "12_REPORTS"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "02_PROOFGRAPH", "receipts"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeJSON(t, filepath.Join(dir, "02_PROOFGRAPH", "receipts", "receipt-001.json"), map[string]any{
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"lamport_clock": 1,
	})

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("unsealed native EvidencePack must fail verification")
	}
	found := false
	for _, c := range report.Checks {
		if c.Name == "evidence_pack_seal" && !c.Pass {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing evidence_pack_seal failure: %+v", report.Checks)
	}
}

func TestVerifyBundleRejectsUntrustedEmbeddedSignatures(t *testing.T) {
	dir := createValidBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), map[string]any{
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"status":        "APPLIED",
		"lamport_clock": 1,
		"signature":     "attacker-controlled",
	})
	sealVerifierFixture(t, dir, "test-session-001")

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatal("bundle with untrusted embedded receipt signature must fail verification")
	}
	var found bool
	for _, check := range report.Checks {
		if check.Name == "embedded_signature_trust" && !check.Pass {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing embedded signature trust failure: %+v", report.Checks)
	}
	if report.SignatureValidCount >= report.SignatureTotalCount {
		t.Fatalf("unverified embedded signature was counted as valid: valid=%d total=%d", report.SignatureValidCount, report.SignatureTotalCount)
	}
}

func TestVerifyBundleAcceptsTrustedManagedAgentReceiptSignature(t *testing.T) {
	dir := createValidBundleFixture(t)
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	decisionHash := "sha256:abc123"
	writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), map[string]any{
		"receipt_version":        "managed_agent_live_scenario_receipt.v1",
		"receipt_id":             "rcpt-001",
		"decision_id":            "dec-001",
		"decision_hash":          decisionHash,
		"status":                 "APPLIED",
		"lamport_clock":          1,
		"scenario_id":            "allowed-bash",
		"signature_algorithm":    "ed25519",
		"signature_payload":      "decision_hash",
		"signer_key_id":          "test-managed-agent-signer",
		"signing_public_key_hex": hex.EncodeToString(pub),
		"signature":              hex.EncodeToString(ed25519.Sign(priv, []byte(decisionHash))),
	})
	sealVerifierFixture(t, dir, "test-session-001")

	report, err := VerifyBundleWithOptions(dir, VerifyOptions{ManagedAgentReceiptPublicKeyHex: hex.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Verified {
		t.Fatalf("trusted managed-agent receipt signature should verify: %s", report.Summary)
	}
	var found bool
	for _, check := range report.Checks {
		if check.Name == "embedded_signature_trust" && check.Pass {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing passing embedded signature trust check: %+v", report.Checks)
	}
}

func TestVerifyBundleMCPPolicyDecisionReceiptTrust(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(pub)
	// Mirrors crypto.CanonicalizeReceipt field order.
	payload := "rcpt-001:dec-001:mcp.tools.call/proof.read:DENY:sha256:out::1:sha256:args"
	signature := hex.EncodeToString(ed25519.Sign(priv, []byte(payload)))
	receipt := func(sig, pubKeyHex string) map[string]any {
		meta := map[string]any{
			"signature_key_type": "ed25519",
			"signature_key_ref":  "ed25519:" + keyHex[:16],
		}
		if pubKeyHex != "" {
			meta["signing_public_key_hex"] = pubKeyHex
		}
		return map[string]any{
			"type":          "mcp_policy_decision",
			"receipt_id":    "rcpt-001",
			"decision_id":   "dec-001",
			"effect_id":     "mcp.tools.call/proof.read",
			"status":        "DENY",
			"output_hash":   "sha256:out",
			"prev_hash":     "",
			"lamport_clock": 1,
			"args_hash":     "sha256:args",
			"signature":     sig,
			"metadata":      meta,
		}
	}

	t.Run("dev-local trusts seal-anchored key disclosure", func(t *testing.T) {
		dir := createValidBundleFixture(t)
		writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), receipt(signature, keyHex))
		sealVerifierFixture(t, dir, "test-session-001")
		report, err := VerifyBundle(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, check := range report.Checks {
			if check.Name == "embedded_signature_trust" && !check.Pass {
				t.Fatalf("dev-local MCP proof receipt signature should verify: %+v", check)
			}
		}
	})

	t.Run("tampered signature fails closed", func(t *testing.T) {
		dir := createValidBundleFixture(t)
		forged := hex.EncodeToString(ed25519.Sign(priv, []byte(payload+"-tampered")))
		writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), receipt(forged, keyHex))
		sealVerifierFixture(t, dir, "test-session-001")
		report, err := VerifyBundle(dir)
		if err != nil {
			t.Fatal(err)
		}
		assertEmbeddedSignatureTrustFails(t, report)
	})

	t.Run("missing key disclosure fails closed", func(t *testing.T) {
		dir := createValidBundleFixture(t)
		writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), receipt(signature, ""))
		sealVerifierFixture(t, dir, "test-session-001")
		report, err := VerifyBundle(dir)
		if err != nil {
			t.Fatal(err)
		}
		assertEmbeddedSignatureTrustFails(t, report)
	})

	t.Run("non-dev-local profile refuses disclosure trust", func(t *testing.T) {
		dir := createValidBundleFixture(t)
		writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), receipt(signature, keyHex))
		sealVerifierFixture(t, dir, "test-session-001")
		report, err := VerifyBundleWithOptions(dir, VerifyOptions{Profile: evidencepkg.EvidenceTrustProfileTeam})
		if err != nil {
			t.Fatal(err)
		}
		assertEmbeddedSignatureTrustFails(t, report)
	})
}

func TestVerifyBundleWitnessSignatureTrust(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	receiptHash := sha256.Sum256([]byte("receipt-payload"))
	receiptHashHex := hex.EncodeToString(receiptHash[:])
	witnessSig := hex.EncodeToString(ed25519.Sign(priv, receiptHash[:]))
	receipt := func(sig string) map[string]any {
		return map[string]any{
			"receipt_id":    "rcpt-001",
			"decision_id":   "dec-001",
			"decision_hash": "sha256:abc123",
			"receipt_hash":  receiptHashHex,
			"status":        "APPLIED",
			"lamport_clock": 1,
			"witness_signatures": []any{
				map[string]any{"witness_id": "w1", "signature": sig},
			},
		}
	}

	t.Run("unconfigured witness keys are skipped, never auto-failed", func(t *testing.T) {
		dir := createValidBundleFixture(t)
		writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), receipt(witnessSig))
		sealVerifierFixture(t, dir, "test-session-001")
		report, err := VerifyBundle(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, check := range report.Checks {
			if check.Name == "embedded_signature_trust" && !check.Pass {
				t.Fatalf("unconfigured witness signatures must not fail the pack: %+v", check)
			}
		}
	})

	t.Run("configured witness key verifies valid signature", func(t *testing.T) {
		dir := createValidBundleFixture(t)
		writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), receipt(witnessSig))
		sealVerifierFixture(t, dir, "test-session-001")
		report, err := VerifyBundleWithOptions(dir, VerifyOptions{
			WitnessPublicKeysHex: map[string]string{"w1": hex.EncodeToString(pub)},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, check := range report.Checks {
			if check.Name == "embedded_signature_trust" && !check.Pass {
				t.Fatalf("valid witness signature should verify against configured key: %+v", check)
			}
		}
	})

	t.Run("configured witness key fails tampered signature closed", func(t *testing.T) {
		dir := createValidBundleFixture(t)
		forged := hex.EncodeToString(ed25519.Sign(priv, []byte("tampered")))
		writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), receipt(forged))
		sealVerifierFixture(t, dir, "test-session-001")
		report, err := VerifyBundleWithOptions(dir, VerifyOptions{
			WitnessPublicKeysHex: map[string]string{"w1": hex.EncodeToString(pub)},
		})
		if err != nil {
			t.Fatal(err)
		}
		assertEmbeddedSignatureTrustFails(t, report)
	})
}

func assertEmbeddedSignatureTrustFails(t *testing.T, report *VerifyReport) {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == "embedded_signature_trust" {
			if check.Pass {
				t.Fatalf("embedded_signature_trust must fail closed: %+v", check)
			}
			return
		}
	}
	t.Fatal("embedded_signature_trust check missing from report")
}

func TestVerifyBundle_MissingManifest(t *testing.T) {
	dir := t.TempDir()

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verified {
		t.Error("expected FAIL for missing manifest")
	}

	// Should fail on structure check
	found := false
	for _, c := range report.Checks {
		if c.Name == "structure" && !c.Pass {
			found = true
		}
	}
	if !found {
		t.Error("expected structure check to fail")
	}
}

func TestVerifyBundle_HashMismatch(t *testing.T) {
	dir := createValidBundleFixture(t)

	// Write a file
	os.WriteFile(filepath.Join(dir, "receipt.json"), []byte(`{"id":"r1"}`), 0o644)

	// Overwrite manifest with wrong hash
	manifest := map[string]any{
		"session_id":  "test-session-002",
		"version":     "1.0.0",
		"exported_at": "2026-01-01T00:00:00Z",
		"file_hashes": map[string]string{
			"receipt.json": "0000000000000000000000000000000000000000000000000000000000000000",
		},
	}
	writeJSON(t, filepath.Join(dir, "manifest.json"), manifest)

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verified {
		t.Error("expected FAIL for hash mismatch")
	}

	hashFailed := false
	for _, c := range report.Checks {
		if c.Name == "hash:receipt.json" && !c.Pass {
			hashFailed = true
		}
	}
	if !hashFailed {
		t.Error("expected hash check to fail for receipt.json")
	}
}

func TestVerifyBundle_IndexHashMismatch(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{
		"version": "1.0.0",
		"entries": []any{
			map[string]any{
				"path":   "01_SCORE.json",
				"sha256": "0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	})

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verified {
		t.Fatal("expected FAIL for indexed hash mismatch")
	}
	found := false
	for _, c := range report.Checks {
		if c.Name == "index_integrity" && !c.Pass {
			found = true
		}
	}
	if !found {
		t.Fatal("expected index_integrity check to fail")
	}
}

func TestVerifyBundle_EUAIActProfileValidatesWhenPresent(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "04_EXPORTS", "ai_act_profile.json"), map[string]any{
		"eu_ai_act_profile": map[string]any{
			"profile_id":                             "eu-ai-act:hr:1",
			"role_map":                               map[string]any{"deployer": "customer"},
			"risk_category":                          "high-risk Annex III employment",
			"relevant_articles":                      []string{"Article 9", "Article 14", "Article 26", "Article 27", "Article 49"},
			"high_risk_reasons":                      []string{"employment and worker management"},
			"provider_or_deployer_role":              "deployer",
			"risk_management_refs":                   []string{"risk:1"},
			"data_governance_refs":                   []string{"data:1"},
			"log_record_refs":                        []string{"logs:1"},
			"transparency_notice_refs":               []string{"instructions:1"},
			"human_oversight_refs":                   []string{"oversight:1"},
			"accuracy_robustness_cybersecurity_refs": []string{"security:1"},
			"fria_refs":                              []string{"fria:1"},
			"affected_person_notice_refs":            []string{"notice:1"},
			"registration_refs":                      []string{"registration:1"},
			"redaction_profile":                      "employment_minimized",
			"timeline_status":                        "FINAL",
			"redaction_metadata":                     map[string]string{"profile": "employment_minimized"},
		},
	})
	sealVerifierFixture(t, dir, "canonical-test")

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Verified {
		t.Fatalf("expected PASS, got %s", report.Summary)
	}
	assertCheck(t, report, "eu_ai_act_profile", true)
}

func TestVerifyBundle_EUAIActProfileRejectsMissingRequiredRefs(t *testing.T) {
	dir := createValidCanonicalBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "04_EXPORTS", "ai_act_profile.json"), map[string]any{
		"eu_ai_act_profile": map[string]any{
			"profile_id":                "eu-ai-act:hr:1",
			"role_map":                  map[string]any{"deployer": "customer"},
			"risk_category":             "high-risk Annex III employment",
			"relevant_articles":         []string{"Article 14"},
			"provider_or_deployer_role": "deployer",
			"redaction_profile":         "employment_minimized",
			"timeline_status":           "FINAL",
		},
	})
	sealVerifierFixture(t, dir, "canonical-test")

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if report.Verified {
		t.Fatal("expected EU AI Act profile failure")
	}
	assertCheck(t, report, "eu_ai_act_profile", false)
}

func TestVerifyBundle_ValidWithHashes(t *testing.T) {
	dir := createValidBundleFixture(t)

	// Write a file and compute correct hash
	content := []byte(`{"id":"r1","type":"receipt"}`)
	os.WriteFile(filepath.Join(dir, "receipt.json"), content, 0o644)
	hash := sha256Hex(content)

	// Overwrite manifest with correct hash
	manifest := map[string]any{
		"session_id":  "test-session-003",
		"version":     "1.0.0",
		"exported_at": "2026-01-01T00:00:00Z",
		"file_hashes": map[string]string{
			"receipt.json": hash,
		},
	}
	writeJSON(t, filepath.Join(dir, "manifest.json"), manifest)
	sealVerifierFixture(t, dir, "test-session-001")

	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !report.Verified {
		t.Errorf("expected PASS, got FAIL: %s", report.Summary)
		for _, c := range report.Checks {
			if !c.Pass {
				t.Logf("  FAIL: %s — %s", c.Name, c.Reason)
			}
		}
	}
}

func TestVerifyBundle_MissingProofGraph(t *testing.T) {
	dir := t.TempDir()

	// Create manifest + index but no proofgraph
	writeJSON(t, filepath.Join(dir, "manifest.json"), map[string]any{"session_id": "s1", "version": "1.0.0"})
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{"version": "1.0.0"})

	// Create receipts so only proofgraph is missing
	receiptsDir := filepath.Join(dir, "receipts")
	os.MkdirAll(receiptsDir, 0o755)
	writeJSON(t, filepath.Join(receiptsDir, "r1.json"), map[string]any{"decision_hash": "sha256:abc"})

	report, _ := VerifyBundle(dir)
	if report.Verified {
		t.Error("expected FAIL for missing proof graph")
	}

	chainFailed := false
	for _, c := range report.Checks {
		if c.Name == "chain_integrity" && !c.Pass {
			chainFailed = true
		}
	}
	if !chainFailed {
		t.Error("expected chain_integrity check to fail")
	}
}

func TestVerifyBundle_MissingReceipts(t *testing.T) {
	dir := t.TempDir()

	// Create manifest + index + proofgraph but no receipts
	writeJSON(t, filepath.Join(dir, "manifest.json"), map[string]any{"session_id": "s1", "version": "1.0.0"})
	writeJSON(t, filepath.Join(dir, "00_INDEX.json"), map[string]any{"version": "1.0.0"})
	writeJSON(t, filepath.Join(dir, "proofgraph.json"), map[string]any{"nodes": []any{}})

	report, _ := VerifyBundle(dir)
	if report.Verified {
		t.Error("expected FAIL for missing receipts")
	}

	lamportFailed := false
	for _, c := range report.Checks {
		if c.Name == "lamport_monotonicity" && !c.Pass {
			lamportFailed = true
		}
	}
	if !lamportFailed {
		t.Error("expected lamport_monotonicity check to fail")
	}
}

func TestVerifyBundle_JSONOutput(t *testing.T) {
	dir := createValidBundleFixture(t)

	report, _ := VerifyBundle(dir)

	// Ensure the report serializes cleanly
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("cannot marshal report: %v", err)
	}
	if len(data) == 0 {
		t.Error("empty JSON output")
	}

	// Roundtrip
	var rt VerifyReport
	if err := json.Unmarshal(data, &rt); err != nil {
		t.Fatalf("cannot unmarshal report: %v", err)
	}
	if rt.Bundle != dir {
		t.Errorf("bundle mismatch after roundtrip")
	}
}

func TestVerifyBundle_GoldenFixtureRoots(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "..", "fixtures", "minimal")
	expectedPath := filepath.Join(fixtureDir, "EXPECTED.json")

	var expected struct {
		BundleRoot string `json:"bundle_root"`
		MerkleRoot string `json:"merkle_root"`
	}
	expectedData, err := os.ReadFile(expectedPath)
	if err != nil {
		t.Fatalf("read expected roots: %v", err)
	}
	if err := json.Unmarshal(expectedData, &expected); err != nil {
		t.Fatalf("parse expected roots: %v", err)
	}

	report, err := VerifyBundle(fixtureDir)
	if err != nil {
		t.Fatalf("verify bundle: %v", err)
	}
	if report.Roots.ManifestRootHash != expected.BundleRoot {
		t.Fatalf("manifest root mismatch: expected %s, got %s", expected.BundleRoot, report.Roots.ManifestRootHash)
	}
	if report.Roots.MerkleRoot != expected.MerkleRoot {
		t.Fatalf("merkle root mismatch: expected %s, got %s", expected.MerkleRoot, report.Roots.MerkleRoot)
	}
	if report.Roots.EntryCount != 2 {
		t.Fatalf("entry count mismatch: expected 2, got %d", report.Roots.EntryCount)
	}
}

func TestCheckConnectorEvidenceAcceptsTinyFishProofRecord(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "connector_evidence.json"), map[string]any{
		"records": []map[string]any{
			{
				"connector_id":            "tinyfish-web-v1",
				"connector_contract_hash": "sha256:contract",
				"policy_hash":             "sha256:policy",
				"request_hash":            "sha256:request",
				"response_hash":           "sha256:response",
				"source_url_hashes":       []string{"sha256:url-1", "sha256:url-2"},
				"receipt_ref":             "receipt://tinyfish/rcpt-1",
				"evidence_pack_ref":       "evidencepack://pack-1",
				"sample_only":             false,
				"production":              true,
			},
		},
	})

	check := checkConnectorEvidence(dir)
	if !check.Pass {
		t.Fatalf("expected connector evidence to pass, got %s", check.Reason)
	}
}

func TestCheckConnectorEvidenceRejectsSampleOnlyProductionPromotion(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "connector_evidence.json"), map[string]any{
		"connector_id":            "tinyfish-web-v1",
		"connector_contract_hash": "sha256:contract",
		"policy_hash":             "sha256:policy",
		"request_hash":            "sha256:request",
		"error_hash":              "sha256:error",
		"source_url_hashes":       []string{"sha256:url-1"},
		"receipt_ref":             "receipt://tinyfish/rcpt-1",
		"evidence_pack_ref":       "evidencepack://pack-1",
		"fixture_id":              "tinyfish-search-sample",
		"sample_only":             true,
		"production":              true,
	})

	check := checkConnectorEvidence(dir)
	if check.Pass {
		t.Fatal("expected sample_only production connector evidence to fail")
	}
	if !strings.Contains(check.Reason, "sample_only_production_exclusion") {
		t.Fatalf("expected sample_only rejection, got %s", check.Reason)
	}
}

func TestCheckConnectorEvidenceRejectsMissingSourceHashes(t *testing.T) {
	dir := t.TempDir()
	writeJSON(t, filepath.Join(dir, "connector_evidence.json"), map[string]any{
		"connector_contract_hash": "sha256:contract",
		"policy_hash":             "sha256:policy",
		"request_hash":            "sha256:request",
		"response_hash":           "sha256:response",
		"receipt_ref":             "receipt://tinyfish/rcpt-1",
		"evidence_pack_ref":       "evidencepack://pack-1",
	})

	check := checkConnectorEvidence(dir)
	if check.Pass {
		t.Fatal("expected missing source_url_hashes to fail")
	}
	if !strings.Contains(check.Reason, "source_url_hashes") {
		t.Fatalf("expected source hash failure, got %s", check.Reason)
	}
}

func assertCheck(t *testing.T, report *VerifyReport, name string, pass bool) {
	t.Helper()
	for _, check := range report.Checks {
		if check.Name == name {
			if check.Pass != pass {
				t.Fatalf("check %s pass = %v, want %v; reason=%s", name, check.Pass, pass, check.Reason)
			}
			return
		}
	}
	t.Fatalf("check %s not found in %#v", name, report.Checks)
}

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
