package verifier

// quantum_posture: these tests exercise classical Ed25519 seal and receipt
// trust-root selection only; they do not assert post-quantum resistance.

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"path/filepath"
	"strings"
	"testing"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
)

// HELM-738: without a trust root the verifier reports UNVERIFIABLE, never a
// pass and never a generic FAIL that reads like tampering.
func TestVerifyBundleWithoutTrustRootIsUnverifiable(t *testing.T) {
	dir := createValidBundleFixture(t)
	t.Setenv("HELM_ALLOW_SELF_ATTESTED_EVIDENCE", "")
	t.Setenv("HELM_EVIDENCE_TRUST_CONFIG", "")
	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", "")
	t.Setenv("HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX", "")
	t.Setenv("HELM_DATA_DIR", t.TempDir())

	report, err := VerifyBundleWithOptions(dir, VerifyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Verified {
		t.Fatalf("pack verified without a trust root: %s", report.Summary)
	}
	if report.SealState != evidencepkg.EvidencePackSealStateUnverifiable {
		t.Fatalf("seal_state=%q, want %q", report.SealState, evidencepkg.EvidencePackSealStateUnverifiable)
	}
	if !strings.HasPrefix(report.Summary, "UNVERIFIABLE:") {
		t.Fatalf("summary=%q, want UNVERIFIABLE", report.Summary)
	}
}

// VC lead 1 (audit 23-07 context): the embedded receipt check used the
// --profile flag while the seal adopted the trust config's active_profile, so
// an empty --profile trusted receipt keys carried inside a team (or customer)
// pack. Both checks must use the one effective profile.
func TestVerifyBundleEmbeddedReceiptsUseSealProfile(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(pub)
	payload := "rcpt-001:dec-001:mcp.tools.call/proof.read:DENY:sha256:out::1:sha256:args"
	dir := createValidBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), map[string]any{
		"type":          "mcp_policy_decision",
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"effect_id":     "mcp.tools.call/proof.read",
		"status":        "DENY",
		"output_hash":   "sha256:out",
		"prev_hash":     "",
		"lamport_clock": 1,
		"args_hash":     "sha256:args",
		"signature":     hex.EncodeToString(ed25519.Sign(priv, []byte(payload))),
		"metadata": map[string]any{
			"signature_key_type":     "ed25519",
			"signature_key_ref":      "ed25519:" + keyHex[:16],
			"signing_public_key_hex": keyHex,
		},
	})
	writeSealFixtureIndex(t, dir)
	sealData := t.TempDir()
	if _, err := evidencepkg.SealEvidencePack(context.Background(), dir, evidencepkg.SealEvidencePackOptions{
		PackID:  "team-pack",
		DataDir: sealData,
	}); err != nil {
		t.Fatal(err)
	}
	signer, err := evidencepkg.NewFileDevEvidenceSigner(sealData)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_ALLOW_SELF_ATTESTED_EVIDENCE", "")
	cfg := &evidencepkg.EvidencePackTrustConfig{
		ActiveProfile: evidencepkg.EvidenceTrustProfileTeam,
		TrustedKeys:   map[string]string{signer.KeyID(): signer.PublicKeyHex()},
	}

	report, err := VerifyBundleWithOptions(dir, VerifyOptions{TrustConfig: cfg})
	if err != nil {
		t.Fatal(err)
	}
	if report.TrustLevel != string(evidencepkg.EvidenceTrustProfileTeam) || report.SealState != "valid" {
		t.Fatalf("seal did not verify at the configured team profile: trust=%s seal=%s", report.TrustLevel, report.SealState)
	}
	if report.Verified {
		t.Fatalf("team pack verified receipts against keys it carries itself: %s", report.Summary)
	}
	assertEmbeddedSignatureTrustFails(t, report)
}

// Audit 23-07: under dev-local, pack-carried receipt keys must be named as
// self-attested, not as "configured trust roots".
func TestEmbeddedSignatureTrustNamesSelfAttestedReceipts(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(pub)
	payload := "rcpt-001:dec-001:mcp.tools.call/proof.read:DENY:sha256:out::1:sha256:args"
	dir := createValidBundleFixture(t)
	writeJSON(t, filepath.Join(dir, "receipts", "receipt-001.json"), map[string]any{
		"type":          "mcp_policy_decision",
		"receipt_id":    "rcpt-001",
		"decision_id":   "dec-001",
		"decision_hash": "sha256:abc123",
		"effect_id":     "mcp.tools.call/proof.read",
		"status":        "DENY",
		"output_hash":   "sha256:out",
		"prev_hash":     "",
		"lamport_clock": 1,
		"args_hash":     "sha256:args",
		"signature":     hex.EncodeToString(ed25519.Sign(priv, []byte(payload))),
		"metadata": map[string]any{
			"signature_key_type":     "ed25519",
			"signature_key_ref":      "ed25519:" + keyHex[:16],
			"signing_public_key_hex": keyHex,
		},
	})
	sealVerifierFixture(t, dir, "test-session-001")
	report, err := VerifyBundle(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range report.Checks {
		if check.Name != "embedded_signature_trust" {
			continue
		}
		if !check.Pass || strings.Contains(check.Detail, "verified against configured trust roots") || !strings.Contains(check.Detail, "self-attested") {
			t.Fatalf("self-attested receipt detail is misleading: %+v", check)
		}
		return
	}
	t.Fatal("missing embedded_signature_trust check")
}
