package main

// quantum_posture: these CLI tests exercise classical Ed25519 trust-root
// selection for EvidencePacks, decision receipts and savings packs; they do
// not cover post-quantum verification.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	proofanchor "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph/anchor"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/verifier/decisionreceipt"
)

// clearVerifierTrustEnv gives the "victim" of the PoCs below a clean trust
// environment: no trusted-key env, no self-attestation opt-in, an empty data dir.
func clearVerifierTrustEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"HELM_EVIDENCE_TRUST_CONFIG",
		"HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX",
		"HELM_EVIDENCE_SIGNER_PUBLIC_KEY_HEX",
		"HELM_ALLOW_SELF_ATTESTED_EVIDENCE",
	} {
		t.Setenv(key, "")
	}
	t.Setenv("HELM_DATA_DIR", t.TempDir())
}

// shipPack moves a sealed pack to <ship>/pack and writes cfg beside it as
// <ship>/helm/helm.yaml, the layout of the verifier PoCs VC ship2 and ship19.
func shipPack(t *testing.T, packDir string, cfg evidencepkg.EvidencePackTrustConfig) string {
	t.Helper()
	shipDir := t.TempDir()
	if err := os.Rename(packDir, filepath.Join(shipDir, "pack")); err != nil {
		t.Fatal(err)
	}
	if _, err := evidencepkg.SaveEvidencePackTrustConfigWithPath(filepath.Join(shipDir, "helm", "helm.yaml"), t.TempDir(), cfg); err != nil {
		t.Fatal(err)
	}
	return shipDir
}

func decodeVerifyReport(t *testing.T, out []byte) map[string]any {
	t.Helper()
	var report map[string]any
	if err := json.Unmarshal(out, &report); err != nil {
		t.Fatalf("parse verify json: %v\n%s", err, out)
	}
	return report
}

// VC 13-01 (ship2): an attacker's pack plus a helm/helm.yaml beside it naming
// the attacker's key at the team profile used to verify from that directory.
func TestVerifyIgnoresTrustConfigShippedBesidePack(t *testing.T) {
	attackerData := t.TempDir()
	packDir := writeCLISealedPack(t, attackerData)
	signer, err := evidencepkg.NewFileDevEvidenceSigner(attackerData)
	if err != nil {
		t.Fatal(err)
	}
	shipDir := shipPack(t, packDir, evidencepkg.EvidencePackTrustConfig{
		ActiveProfile: evidencepkg.EvidenceTrustProfileTeam,
		Signer:        evidencepkg.EvidencePackTrustSigner{Type: "file-dev", KeyID: signer.KeyID(), PublicKey: signer.PublicKeyHex()},
		TrustedKeys:   map[string]string{signer.KeyID(): signer.PublicKeyHex()},
	})
	clearVerifierTrustEnv(t)
	t.Chdir(shipDir)

	var stdout, stderr bytes.Buffer
	if code := runVerifyCmd([]string{"--bundle", "pack", "--json"}, &stdout, &stderr); code != 1 {
		t.Fatalf("verify exit=%d, want 1; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	report := decodeVerifyReport(t, stdout.Bytes())
	if report["verified"] != false || report["seal_state"] != evidencepkg.EvidencePackSealStateUnverifiable || report["trust_level"] == "team" {
		t.Fatalf("pack verified against trust shipped beside it: %s", stdout.String())
	}
	if !strings.HasPrefix(report["summary"].(string), "UNVERIFIABLE:") {
		t.Fatalf("summary does not say UNVERIFIABLE: %s", report["summary"])
	}

	stdout.Reset()
	if code := runVerifyCmd([]string{"--bundle", "pack"}, &stdout, &stderr); code != 1 || !strings.HasPrefix(stdout.String(), "UNVERIFIABLE · ") {
		t.Fatalf("text verify exit=%d, want UNVERIFIABLE headline: %s", code, stdout.String())
	}

	// Naming the same file explicitly is the operator's choice and still works.
	stdout.Reset()
	if code := runVerifyCmd([]string{"--bundle", "pack", "--config", filepath.Join("helm", "helm.yaml"), "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("explicit --config exit=%d, want 0; stdout=%s", code, stdout.String())
	}
	if report := decodeVerifyReport(t, stdout.Bytes()); report["trust_level"] != "team" {
		t.Fatalf("explicit --config trust level = %v, want team", report["trust_level"])
	}
	t.Setenv("HELM_EVIDENCE_TRUST_CONFIG", filepath.Join(shipDir, "helm", "helm.yaml"))
	stdout.Reset()
	if code := runVerifyCmd([]string{"--bundle", "pack", "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("HELM_EVIDENCE_TRUST_CONFIG exit=%d, want 0; stdout=%s", code, stdout.String())
	}
}

// VC 19-01 (ship19): a customer-profile pack with a forged RFC 3161 anchor (a
// DER INTEGER, backdated to 2020) beside a helm/helm.yaml that trusts the
// attacker's key. B2 reached trust=customer from the working directory alone;
// B1 (an insider whose key the operator trusts) passed the anchor check.
func TestVerifyRejectsForgedAnchorShippedBesidePack(t *testing.T) {
	packDir := writeCLISealedPack(t, t.TempDir())
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyHex := hex.EncodeToString(publicKey)
	cfg := evidencepkg.EvidencePackTrustConfig{
		Version:       "evidence-pack-trust/v1",
		ActiveProfile: evidencepkg.EvidenceTrustProfileCustomer,
		Signer:        evidencepkg.EvidencePackTrustSigner{Type: "kms", KeyID: "kms:attacker", KMSKeyID: "kms:attacker", PublicKey: keyHex},
		Anchor:        evidencepkg.EvidencePackSealAnchor{Type: "rfc3161", URL: "https://tsa.invalid/", Status: "configured"},
		Storage:       evidencepkg.EvidencePackSealStorage{Type: "s3", Bucket: "audit", ObjectLock: true, Immutable: true, Status: "configured"},
		TrustedKeys:   map[string]string{"kms:attacker": keyHex},
	}
	roots, err := evidencepkg.ComputeEvidencePackIndexRoots(packDir)
	if err != nil {
		t.Fatal(err)
	}
	forged, err := asn1.Marshal(42)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), packDir, evidencepkg.SealEvidencePackOptions{
		PackID:      "forged-anchor-pack",
		Profile:     evidencepkg.EvidenceTrustProfileCustomer,
		TrustConfig: &cfg,
		Signer:      cliFakeEvidenceSigner{keyID: "kms:attacker", privateKey: privateKey, publicKey: publicKey},
		AnchorReceipts: []proofanchor.AnchorReceipt{{
			Backend:        "rfc3161",
			Request:        proofanchor.AnchorRequest{MerkleRoot: roots.MerkleRoot},
			LogID:          "https://tsa.invalid/",
			IntegratedTime: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
			Signature:      base64.StdEncoding.EncodeToString(forged),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	shipDir := shipPack(t, packDir, cfg)
	storageReceipt := filepath.Join(shipDir, "storage-receipt.json")
	if err := evidencepkg.WriteStorageReceipt(storageReceipt, evidencepkg.EvidencePackStorageReceipt{
		SchemaVersion: evidencepkg.EvidencePackStorageReceiptSchemaS3,
		StorageType:   "s3-object-lock",
		SubjectRoot:   roots.MerkleRoot,
		Bucket:        "audit",
		Key:           "packs/forged-anchor-pack.tar",
		VersionID:     "v1",
		ObjectHash:    "sha256:" + strings.Repeat("a", 64),
		RetentionMode: "COMPLIANCE",
		RetainUntil:   time.Now().UTC().Add(24 * time.Hour),
		StoredAt:      time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	clearVerifierTrustEnv(t)
	t.Chdir(shipDir)

	// B2: no flags, trust only from the working directory.
	var stdout, stderr bytes.Buffer
	if code := runVerifyCmd([]string{"--bundle", "pack", "--json"}, &stdout, &stderr); code != 1 {
		t.Fatalf("B2 verify exit=%d, want 1; stdout=%s", code, stdout.String())
	}
	if report := decodeVerifyReport(t, stdout.Bytes()); report["verified"] != false || report["trust_level"] == "customer" {
		t.Fatalf("B2 reached customer trust from the working directory: %s", stdout.String())
	}

	// B1: the operator explicitly trusts the signer, but the anchor must still
	// bind the pack root.
	stdout.Reset()
	code := runVerifyCmd([]string{"--bundle", "pack", "--config", filepath.Join("helm", "helm.yaml"), "--profile", "customer", "--storage-receipt", storageReceipt, "--json"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stdout.String(), "rfc3161") {
		t.Fatalf("B1 forged anchor verify exit=%d, want 1 with an rfc3161 anchor failure; stdout=%s", code, stdout.String())
	}
	if report := decodeVerifyReport(t, stdout.Bytes()); report["anchor_status"] == "verified-externally" {
		t.Fatalf("forged anchor reported verified-externally: %s", stdout.String())
	}
}

// Audit 04-06: a decision receipt whose only key is disclosed in the bundle
// itself printed VERIFIED and exited 0.
func TestVerifyDecisionReceiptDisclosedKeyIsUnverifiable(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := decisionreceipt.SignHelmExternal(contracts.ExternalDecisionReceipt{
		ReceiptID: "edr_forged_1", Action: "github.delete_repo", Verdict: "allow",
	}, priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(contracts.ExternalDecisionReceiptBundle{
		SchemaVersion: contracts.ExternalDecisionReceiptBundleVersion,
		FormatID:      decisionreceipt.HelmExternalFormatID,
		PublicKeys:    []contracts.ExternalVerifierKey{{KeyID: "self", Algorithm: "ed25519", PublicKeyHex: hex.EncodeToString(pub)}},
		Receipts:      []contracts.ExternalDecisionReceipt{signed},
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	if code := runVerifyDecisionReceiptCmd([]string{path}, &out, &errb); code != 1 {
		t.Fatalf("exit=%d, want 1; stdout=%s", code, out.String())
	}
	if !strings.HasPrefix(out.String(), "UNVERIFIABLE") {
		t.Fatalf("disclosed-key bundle headline: %s", out.String())
	}
	out.Reset()
	if code := runVerifyDecisionReceiptCmd([]string{path, "--json"}, &out, &errb); code != 1 || !strings.Contains(out.String(), `"verified": false`) {
		t.Fatalf("json exit=%d, want 1 and verified false: %s", code, out.String())
	}
	out.Reset()
	if code := runVerifyDecisionReceiptCmd([]string{path, "--public-key", hex.EncodeToString(pub)}, &out, &errb); code != 0 {
		t.Fatalf("trusted key exit=%d, want 0: %s", code, out.String())
	}
}

// Audit 13-04: savings-verify reported ok=true against the key registry the
// pack carries itself. The reference pack's issuer pair is published with the
// capture record (HELM-618) and in the walkthrough.
func TestSpendProxySavingsVerifyRequiresPinnedIssuer(t *testing.T) {
	const (
		pack      = "../../../reference_packs/spend-savings/savingspack-h618-infnet-20260818"
		issuerID  = "spend-proxy-d11333ad0bbd"
		issuerHex = "66b4789478701145b64834a7293cb14d94fd8b6bbf34c370bf39e483ab19c5e6"
	)
	var stdout, stderr bytes.Buffer
	if code := runSpendProxyCmd([]string{"savings-verify", "--pack", pack}, &stdout, &stderr); code != 1 || !strings.Contains(stdout.String(), "UNVERIFIABLE") {
		t.Fatalf("unpinned exit=%d, want 1 and UNVERIFIABLE; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := runSpendProxyCmd([]string{"savings-verify", "--pack", pack, "--issuer-key-id", issuerID, "--issuer-public-key", issuerHex}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "offline-verified ok=true") {
		t.Fatalf("pinned exit=%d, want 0; stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	if code := runSpendProxyCmd([]string{"savings-verify", "--pack", pack, "--issuer-key-id", issuerID, "--issuer-public-key", hex.EncodeToString(other)}, &stdout, &stderr); code != 1 || !strings.Contains(stderr.String(), "VERIFICATION FAILED") {
		t.Fatalf("wrong pin exit=%d, want 1; stderr=%s", code, stderr.String())
	}
	if code := runSpendProxyCmd([]string{"savings-verify", "--pack", pack, "--issuer-key-id", issuerID}, &stdout, &stderr); code != 2 {
		t.Fatalf("half pin exit=%d, want 2", code)
	}
}

// Audit 02-08, second site: launch evidence refs come from a local run record,
// so a pack signed by a key other than the launch store's own must not verify.
func TestLaunchEvidenceRefsRejectForeignSignedPack(t *testing.T) {
	clearVerifierTrustEnv(t)
	storeRoot := t.TempDir()
	packDir := writeCLISealedPack(t, t.TempDir())
	checks := verifyLaunchEvidenceRefs([]string{packDir}, storeRoot)
	if len(checks) != 1 || checks[0].Verified {
		t.Fatalf("foreign-signed pack verified as launch evidence: %+v", checks)
	}
	if !strings.HasPrefix(checks[0].Summary, "UNVERIFIABLE") {
		t.Fatalf("summary = %q, want UNVERIFIABLE", checks[0].Summary)
	}
}
