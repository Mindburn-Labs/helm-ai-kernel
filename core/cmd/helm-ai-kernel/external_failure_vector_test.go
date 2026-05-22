package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTestConformanceVectorValidatesExternalFailureVector(t *testing.T) {
	vector := `{
  "id": "HCV-2026-00001",
  "vector_id": "HCV-2026-00001",
  "candidate_id": "efi-2026-0001",
  "hpr_id": "HPR-2026-00001",
  "failure_mode": "PROMPT_INJECTION_TOOL_HIJACK",
  "title": "prompt_injection_tool_hijack_must_deny",
  "template": "prompt_injection_tool_hijack_must_deny",
  "level": "L2",
  "policy_profile": "public_replay_v1",
  "input": {"plan_ir": "plan_ir.json", "policy": "policy.toml", "fixtures": ["fixtures/source_payload.redacted.json"]},
  "expected": {"verdict": "DENY", "reason_code": "ERR_PROMPT_INJECTION_TOOL_HIJACK", "receipt_required": true, "evidencepack_required": true},
  "negative_assertions": ["must_not_dispatch_connector", "must_not_store_sensitive_payload_in_cleartext", "must_not_publish_raw_source_payload"],
  "expected_verdict": "DENY",
  "expected_reason_code": "ERR_PROMPT_INJECTION_TOOL_HIJACK",
  "must_emit_receipt": true,
  "must_not_dispatch": true,
  "must_bind_evidence": true
}`
	path := filepath.Join(t.TempDir(), "vector.json")
	if err := os.WriteFile(path, []byte(vector), 0o600); err != nil {
		t.Fatalf("write vector: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runTestCmd([]string{"conformance", "--vector", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runTestCmd exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "PASS") {
		t.Fatalf("stdout missing PASS: %s", stdout.String())
	}
}

func TestTestConformanceVectorWritesSignedKernelValidationManifest(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	t.Setenv("HELM_SIGNING_KEY_HEX", hex.EncodeToString(seed))
	t.Setenv("HELM_FIXED_TIME_RFC3339", "2026-05-22T10:00:00Z")

	vectorPath := writeExternalFailureVectorFixture(t)
	manifestPath := filepath.Join(t.TempDir(), "kernel-validation.json")
	evidencePackPath := filepath.Join("..", "..", "..", "reference_packs", "proof_replays", "HPR-2026-00001", "evidencepack.tar")
	var stdout, stderr bytes.Buffer
	code := runTestCmd([]string{
		"conformance",
		"--vector", vectorPath,
		"--validation-manifest", manifestPath,
		"--evidencepack", evidencePackPath,
		"--kernel-commit", "abc123",
		"--json",
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runTestCmd exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	var manifest externalFailureValidationManifest
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if manifest.HPRID != "HPR-2026-00001" || len(manifest.HCVIDs) != 1 || manifest.HCVIDs[0] != "HCV-2026-00001" {
		t.Fatalf("manifest replay/vector linkage = %+v", manifest)
	}
	if !strings.HasPrefix(manifest.EvidencePackHash, "sha256:") || manifest.KernelCommit != "abc123" {
		t.Fatalf("manifest missing pack hash or commit: %+v", manifest)
	}
	signature, err := hex.DecodeString(manifest.Signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	manifest.Signature = ""
	payload, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatalf("canonical manifest: %v", err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		t.Fatal("manifest signature did not verify")
	}
}

func TestVerifyProofReplayEvidencePackTar(t *testing.T) {
	evidencePackPath := filepath.Join("..", "..", "..", "reference_packs", "proof_replays", "HPR-2026-00001", "evidencepack.tar")
	var stdout, stderr bytes.Buffer
	code := runVerifyCmd([]string{evidencePackPath, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("runVerifyCmd exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), `"verified": true`) {
		t.Fatalf("verify output did not pass: %s", stdout.String())
	}
}

func TestVerifyMissingProofReplayEvidencePackFails(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runVerifyCmd([]string{filepath.Join(t.TempDir(), "missing.evidencepack.tar"), "--json"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("missing EvidencePack unexpectedly passed stdout=%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "verification failed") {
		t.Fatalf("missing EvidencePack stderr = %s", stderr.String())
	}
}

func TestExternalFailureVectorRejectsMalformedHPRAndDispatchAssertions(t *testing.T) {
	vector := externalFailureVector{
		ID:                 "HCV-2026-00001",
		HPRID:              "not-hpr",
		FailureMode:        "PROMPT_INJECTION_TOOL_HIJACK",
		ExpectedVerdict:    "BLOCK",
		ExpectedReasonCode: "ERR_PROMPT_INJECTION_TOOL_HIJACK",
		MustEmitReceipt:    true,
		MustNotDispatch:    false,
		MustBindEvidence:   true,
		NegativeAssertions: []string{"must_not_publish_raw_source_payload"},
	}
	vector.Expected.ReceiptRequired = true
	vector.Expected.EvidencePackRequired = true
	issues := validateExternalFailureVector(vector)
	joined := strings.Join(issues, "\n")
	for _, want := range []string{
		"source replay id must use HPR prefix",
		"expected verdict must be ALLOW, DENY, or ESCALATE",
		"vector must assert no connector dispatch",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("issues missing %q: %v", want, issues)
		}
	}
}

func writeExternalFailureVectorFixture(t *testing.T) string {
	t.Helper()
	vector := `{
  "id": "HCV-2026-00001",
  "vector_id": "HCV-2026-00001",
  "candidate_id": "efi-2026-0001",
  "hpr_id": "HPR-2026-00001",
  "failure_mode": "PROMPT_INJECTION_TOOL_HIJACK",
  "title": "prompt_injection_tool_hijack_must_deny",
  "template": "prompt_injection_tool_hijack_must_deny",
  "level": "L2",
  "policy_profile": "public_replay_v1",
  "input": {"plan_ir": "plan_ir.json", "policy": "policy.toml", "fixtures": ["fixtures/source_payload.redacted.json"]},
  "expected": {"verdict": "DENY", "reason_code": "ERR_PROMPT_INJECTION_TOOL_HIJACK", "receipt_required": true, "evidencepack_required": true},
  "negative_assertions": ["must_not_dispatch_connector", "must_not_store_sensitive_payload_in_cleartext", "must_not_publish_raw_source_payload"],
  "expected_verdict": "DENY",
  "expected_reason_code": "ERR_PROMPT_INJECTION_TOOL_HIJACK",
  "must_emit_receipt": true,
  "must_not_dispatch": true,
  "must_bind_evidence": true
}`
	path := filepath.Join(t.TempDir(), "vector.json")
	if err := os.WriteFile(path, []byte(vector), 0o600); err != nil {
		t.Fatalf("write vector: %v", err)
	}
	return path
}
