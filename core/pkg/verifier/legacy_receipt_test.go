// quantum_posture: these tests exercise the pack verifier's classical Ed25519
// receipt checks only; they add no signature scheme and claim no hybrid or
// post-quantum protection.
package verifier

import (
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

// verifyLegacyDevLocalBundle is VerifyBundle with the legacy opt-in. The
// tests whose fixtures are unversioned dev-local MCP proof receipts use it, so
// that each still passes or fails for the reason it names and not because an
// unversioned receipt is no longer checked by default.
func verifyLegacyDevLocalBundle(dir string) (*VerifyReport, error) {
	return VerifyBundleWithOptions(dir, VerifyOptions{Profile: evidencepkg.EvidenceTrustProfileDevLocal, AllowLegacyV4Receipts: true})
}

// embeddedSignatureTrust returns the pack verifier's embedded_signature_trust
// check for a sealed fixture pack holding one receipt document.
func embeddedSignatureTrust(t *testing.T, receipt map[string]any, opts VerifyOptions) CheckResult {
	t.Helper()
	dir := createValidBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), receipt)
	sealVerifierFixture(t, dir, "test-session-001")
	report, err := VerifyBundleWithOptions(dir, opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range report.Checks {
		if check.Name == "embedded_signature_trust" {
			return check
		}
	}
	t.Fatalf("embedded_signature_trust check missing from report: %+v", report.Checks)
	return CheckResult{}
}

// TestDevLocalMCPReceiptIsNotCheckedAsLegacyByDefault is helm-tracker#305
// defect B in the pack verifier. Its dev-local MCP branch checked an
// unversioned receipt against eight colon-joined fields under the key the
// receipt carries. The signature of a genuine receipt.v5 DENY read back as
// those eight fields, with the real runtime key beside it and
// "type":"mcp_governed_effect_execution" added, passed
// embedded_signature_trust for a receipt that says ALLOW. No key is needed to
// build it. An unversioned receipt is now checked only under
// VerifyOptions.AllowLegacyV4Receipts, and the replay is refused under it too.
func TestDevLocalMCPReceiptIsNotCheckedAsLegacyByDefault(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(pub)
	devLocal := VerifyOptions{Profile: evidencepkg.EvidenceTrustProfileDevLocal}
	optedIn := VerifyOptions{Profile: evidencepkg.EvidenceTrustProfileDevLocal, AllowLegacyV4Receipts: true}

	// A genuine receipt.v5 DENY, as the runtime signs it.
	signed, err := canonicalize.InteroperableJCS(receiptV5DocumentEnvelope{
		SignatureVersion: "receipt.v5", ReceiptID: "rcpt-1", DecisionID: "dec-1", EffectID: "eff-1", Status: "DENIED",
		OutputHash: "sha256:out", ArgsHash: "sha256:args", LamportClock: 1,
		Verdict: "DENY", ReasonCode: "POLICY_DENY", PolicyHash: "sha256:policy", SessionID: "tenant-a:7:agent-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := hex.EncodeToString(ed25519.Sign(priv, signed))

	// The same bytes read back as the eight fields of the legacy preimage.
	var replay map[string]any
	parts := strings.Split(string(signed), ":")
	for i := 6; i < len(parts)-1 && replay == nil; i++ {
		clock, err := strconv.ParseUint(parts[i], 10, 64)
		if err != nil || strconv.FormatUint(clock, 10) != parts[i] {
			continue
		}
		replay = map[string]any{
			"receipt_id": parts[0], "decision_id": parts[1], "effect_id": parts[2], "status": parts[3], "output_hash": parts[4],
			"prev_hash": strings.Join(parts[5:i], ":"), "lamport_clock": clock, "args_hash": strings.Join(parts[i+1:], ":"),
			"verdict": "ALLOW", "tool_name": "wire_transfer", "signature": signature,
			"type": "mcp_governed_effect_execution", "signature_profile": "classical", "signature_algorithm": "ed25519",
			"public_key_set": map[string]any{"ed25519": keyHex},
		}
	}
	if replay == nil {
		t.Fatal("the signed receipt.v5 bytes hold no colon-delimited integer to stand in for lamport_clock; the case proves nothing")
	}
	legacyPreimage := strings.Join([]string{
		replay["receipt_id"].(string), replay["decision_id"].(string), replay["effect_id"].(string), replay["status"].(string),
		replay["output_hash"].(string), replay["prev_hash"].(string), strconv.FormatUint(replay["lamport_clock"].(uint64), 10), replay["args_hash"].(string),
	}, ":")
	if legacyPreimage != string(signed) || !ed25519.Verify(pub, []byte(legacyPreimage), ed25519.Sign(priv, signed)) {
		t.Fatal("the planted receipt is not a legacy reading of the signed receipt.v5 bytes; the case proves nothing")
	}

	if check := embeddedSignatureTrust(t, replay, devLocal); check.Pass {
		t.Fatalf("the signature of a receipt.v5 DENY, replayed as an unversioned ALLOW receipt, passed embedded_signature_trust: %+v", check)
	}
	if check := embeddedSignatureTrust(t, replay, optedIn); check.Pass {
		t.Fatalf("the replay passed embedded_signature_trust under the legacy opt-in; its receipt_id begins with \"{\": %+v", check)
	}

	// A genuine legacy MCP proof receipt, signed over the legacy preimage.
	const effectID = "mcp_governed_effect_execution/proof.local_write"
	legacy := map[string]any{
		"receipt_id": "exec-001", "decision_id": "dec-001", "effect_id": effectID, "status": "APPLIED",
		"output_hash": "sha256:out", "prev_hash": "", "lamport_clock": 1, "args_hash": "sha256:args",
		"signature":         hex.EncodeToString(ed25519.Sign(priv, []byte("exec-001:dec-001:"+effectID+":APPLIED:sha256:out::1:sha256:args"))),
		"signature_profile": "classical", "signature_algorithm": "ed25519",
		"public_key_set": map[string]any{"ed25519": keyHex},
	}
	if check := embeddedSignatureTrust(t, legacy, devLocal); check.Pass {
		t.Fatalf("an unversioned receipt was checked without the opt-in: %+v", check)
	}
	if check := embeddedSignatureTrust(t, legacy, optedIn); !check.Pass {
		t.Fatalf("a genuine legacy dev-local MCP receipt must still verify under AllowLegacyV4Receipts: %+v", check)
	}

	// A receipt.v5 MCP proof receipt needs no opt-in.
	const policyEffectID = "mcp_policy_decision/proof.read"
	v5Signed, err := canonicalize.InteroperableJCS(receiptV5DocumentEnvelope{
		SignatureVersion: "receipt.v5", ReceiptID: "rcpt-2", DecisionID: "dec-2", EffectID: policyEffectID, Status: "DENY",
		OutputHash: "sha256:out", ArgsHash: "sha256:args", LamportClock: 1,
		Verdict: "DENY", ReasonCode: "POLICY_DENY", PolicyHash: "sha256:policy", SessionID: "session",
	})
	if err != nil {
		t.Fatal(err)
	}
	current := map[string]any{
		"signature_version": "receipt.v5", "receipt_id": "rcpt-2", "decision_id": "dec-2", "effect_id": policyEffectID, "status": "DENY",
		"output_hash": "sha256:out", "prev_hash": "", "args_hash": "sha256:args", "lamport_clock": 1,
		"verdict": "DENY", "reason_code": "POLICY_DENY", "policy_hash": "sha256:policy", "session_id": "session",
		"signature":         hex.EncodeToString(ed25519.Sign(priv, v5Signed)),
		"signature_profile": "classical", "signature_algorithm": "ed25519",
		"public_key_set": map[string]any{"ed25519": keyHex},
	}
	if check := embeddedSignatureTrust(t, current, devLocal); !check.Pass {
		t.Fatalf("a receipt.v5 dev-local MCP receipt must verify with no opt-in: %+v", check)
	}
}

// TestUncheckedLegacyReceiptIsReportedAsNotChecked is helm-tracker#305 round
// 2 note 5. A dev-local MCP proof receipt with no signature_version is left
// unchecked by default, and embedded_signature_trust said its signature
// "require[s] a configured verifier; none are trusted by presence alone",
// which reads as a missing key, not as a receipt that was never checked. The
// reason now says that and names the opt-in. A receipt.v5 receipt whose
// signature fails is not reported as unchecked.
func TestUncheckedLegacyReceiptIsReportedAsNotChecked(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(pub)
	devLocal := VerifyOptions{Profile: evidencepkg.EvidenceTrustProfileDevLocal}

	const effectID = "mcp_governed_effect_execution/proof.local_write"
	legacy := map[string]any{
		"receipt_id": "exec-001", "decision_id": "dec-001", "effect_id": effectID, "status": "APPLIED",
		"output_hash": "sha256:out", "prev_hash": "", "lamport_clock": 1, "args_hash": "sha256:args",
		"signature":         hex.EncodeToString(ed25519.Sign(priv, []byte("exec-001:dec-001:"+effectID+":APPLIED:sha256:out::1:sha256:args"))),
		"signature_profile": "classical", "signature_algorithm": "ed25519",
		"public_key_set": map[string]any{"ed25519": keyHex},
	}
	check := embeddedSignatureTrust(t, legacy, devLocal)
	if check.Pass {
		t.Fatalf("an unversioned receipt was checked without the opt-in: %+v", check)
	}
	if !strings.Contains(check.Reason, "not checked: no signature_version") || !strings.Contains(check.Reason, "--allow-legacy-v4-receipts") {
		t.Fatalf("the refusal must say the receipt was not checked for want of a signature_version and name the opt-in, got %q", check.Reason)
	}
	if strings.Contains(check.Reason, "trusted by presence alone") {
		t.Fatalf("the refusal must not read as a missing trust root, got %q", check.Reason)
	}

	// A receipt.v5 MCP receipt whose signature does not verify was checked.
	signed, err := canonicalize.InteroperableJCS(receiptV5DocumentEnvelope{
		SignatureVersion: "receipt.v5", ReceiptID: "rcpt-2", DecisionID: "dec-2", EffectID: effectID, Status: "APPLIED",
		OutputHash: "sha256:out", ArgsHash: "sha256:args", LamportClock: 1,
		Verdict: "DENY", ReasonCode: "POLICY_DENY", PolicyHash: "sha256:policy", SessionID: "session",
	})
	if err != nil {
		t.Fatal(err)
	}
	tampered := map[string]any{
		"signature_version": "receipt.v5", "receipt_id": "rcpt-2", "decision_id": "dec-2", "effect_id": effectID, "status": "APPLIED",
		"output_hash": "sha256:out", "prev_hash": "", "args_hash": "sha256:args", "lamport_clock": 1,
		"verdict": "ALLOW", "reason_code": "POLICY_DENY", "policy_hash": "sha256:policy", "session_id": "session",
		"signature":         hex.EncodeToString(ed25519.Sign(priv, signed)),
		"signature_profile": "classical", "signature_algorithm": "ed25519",
		"public_key_set": map[string]any{"ed25519": keyHex},
	}
	check = embeddedSignatureTrust(t, tampered, devLocal)
	if check.Pass || strings.Contains(check.Reason, "not checked") {
		t.Fatalf("a receipt.v5 receipt whose signature fails must fail and must not be reported as unchecked: %+v", check)
	}
}
