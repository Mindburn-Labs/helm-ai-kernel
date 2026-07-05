package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	evidencepkg "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/evidence"
	proofanchor "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph/anchor"
)

type cliFakeEvidenceSigner struct {
	keyID      string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func (s cliFakeEvidenceSigner) KeyID() string { return s.keyID }

func (s cliFakeEvidenceSigner) PublicKeyHex() string { return hex.EncodeToString(s.publicKey) }

func (s cliFakeEvidenceSigner) SignerType() string { return "kms" }

func (s cliFakeEvidenceSigner) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(s.privateKey, payload), nil
}

func TestVerifyProfileDevLocalPassesSealedPack(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLISealedPack(t, dataDir)

	var stdout, stderr bytes.Buffer
	code := runVerifyCmd([]string{"--profile", "dev-local", packDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "seal valid") || !strings.Contains(stdout.String(), "trust dev-local") {
		t.Fatalf("compact output missing seal/trust state: %s", stdout.String())
	}
}

func TestVerifyProfileDevLocalPassesDeclaredIndexedExtension(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLISealedPack(t, dataDir, "helm-formal-proof")

	var stdout, stderr bytes.Buffer
	code := runVerifyCmd([]string{"--profile", "dev-local", packDir}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "VERIFIED") {
		t.Fatalf("compact output missing verification state: %s", stdout.String())
	}
}

func TestVerifyProfileCustomerFailsWithoutExternalTrust(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLISealedPack(t, dataDir)

	var stdout, stderr bytes.Buffer
	code := runVerifyCmd([]string{"--profile", "customer", packDir, "--json"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("customer verify exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), "requires an external signer") || !strings.Contains(stdout.String(), "requires an external anchor") {
		t.Fatalf("customer profile did not fail closed on local-dev seal: %s", stdout.String())
	}
}

func TestEvidenceTrustInitWritesLocalConfig(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	var stdout, stderr bytes.Buffer
	code := runEvidenceTrustInit([]string{"--signer", "file-dev", "--anchor", "local-dev", "--store", "local-dev", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("trust init exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	configPath := evidencepkg.EvidencePackTrustConfigPath(dataDir)
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("trust config missing: %v", err)
	}
	if _, err := os.Stat(evidencepkg.FileDevEvidenceKeyPath(dataDir)); err != nil {
		t.Fatalf("file-dev key missing: %v", err)
	}
	if !strings.Contains(stdout.String(), `"active_profile": "dev-local"`) {
		t.Fatalf("json output missing profile: %s", stdout.String())
	}
}

func TestTrustInitTopLevelWritesHelmYAMLConfig(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	configPath := filepath.Join(t.TempDir(), "helm", "helm.yaml")
	var stdout, stderr bytes.Buffer
	code := runTrustCmd([]string{"init", "--config", configPath, "--signer", "file-dev", "--anchor", "local-dev", "--store", "local-dev", "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("trust init exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("trust config missing: %v", err)
	}
	if !strings.Contains(string(data), "evidence_pack:") || !strings.Contains(string(data), "profile: dev-local") {
		t.Fatalf("helm.yaml missing native evidence trust config:\n%s", data)
	}
	if _, err := evidencepkg.LoadEvidencePackTrustConfigWithPath(configPath, dataDir); err != nil {
		t.Fatalf("load helm.yaml trust config: %v", err)
	}
}

func TestVerifyProfileCustomerPassesWithAnchorAndStorageReceipt(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("HELM_DATA_DIR", dataDir)
	packDir := writeCLISealedPack(t, dataDir)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := evidencepkg.EvidencePackTrustConfig{
		Version:       "evidence-pack-trust/v1",
		ActiveProfile: evidencepkg.EvidenceTrustProfileCustomer,
		Signer: evidencepkg.EvidencePackTrustSigner{
			Type:      "kms",
			KeyID:     "kms-key",
			KMSKeyID:  "kms-key",
			PublicKey: hex.EncodeToString(publicKey),
		},
		Anchor: evidencepkg.EvidencePackSealAnchor{Type: "rfc3161", URI: "http://tsa.example", Status: "configured"},
		Storage: evidencepkg.EvidencePackSealStorage{
			Type:       "s3",
			Bucket:     "customer-audit",
			ObjectLock: true,
			Immutable:  true,
			Status:     "configured",
		},
		TrustedKeys: map[string]string{"kms-key": hex.EncodeToString(publicKey)},
		UpdatedAt:   time.Now().UTC(),
	}
	if _, err := evidencepkg.SaveEvidencePackTrustConfig(dataDir, cfg); err != nil {
		t.Fatal(err)
	}
	token, err := asn1.Marshal(1)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := evidencepkg.ComputeEvidencePackIndexRoots(packDir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = evidencepkg.SealEvidencePack(context.Background(), packDir, evidencepkg.SealEvidencePackOptions{
		PackID:      "customer-pack",
		Profile:     evidencepkg.EvidenceTrustProfileCustomer,
		TrustConfig: &cfg,
		Signer: cliFakeEvidenceSigner{
			keyID:      "kms-key",
			privateKey: privateKey,
			publicKey:  publicKey,
		},
		AnchorReceipts: []proofanchor.AnchorReceipt{{
			Backend:   "rfc3161",
			Request:   proofanchor.AnchorRequest{MerkleRoot: roots.MerkleRoot},
			LogID:     "http://tsa.example",
			Signature: base64.StdEncoding.EncodeToString(token),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt := evidencepkg.EvidencePackStorageReceipt{
		SchemaVersion: evidencepkg.EvidencePackStorageReceiptSchemaS3,
		StorageType:   "s3-object-lock",
		SubjectRoot:   roots.MerkleRoot,
		Bucket:        "customer-audit",
		Key:           "packs/customer-pack.tar",
		VersionID:     "version-1",
		ObjectHash:    "sha256:" + strings.Repeat("a", 64),
		RetentionMode: "COMPLIANCE",
		RetainUntil:   time.Now().UTC().Add(24 * time.Hour),
		StoredAt:      time.Now().UTC(),
	}
	receiptPath := filepath.Join(t.TempDir(), "storage.json")
	if err := evidencepkg.WriteStorageReceipt(receiptPath, receipt); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runVerifyCmd([]string{"--profile", "customer", "--storage-receipt", receiptPath, packDir, "--json"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("customer verify exit=%d stderr=%s stdout=%s", code, stderr.String(), stdout.String())
	}
	if !strings.Contains(stdout.String(), `"storage_status": "immutable-off-host"`) || !strings.Contains(stdout.String(), `"anchor_status": "verified-externally"`) {
		t.Fatalf("customer verify missing receipt statuses: %s", stdout.String())
	}
}

func writeCLISealedPack(t *testing.T, dataDir string, extensions ...string) string {
	t.Helper()
	dir := t.TempDir()
	score := []byte(`{"pass":true}`)
	if err := os.WriteFile(filepath.Join(dir, "01_SCORE.json"), score, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, subdir := range []string{"02_PROOFGRAPH", "03_TELEMETRY", "04_EXPORTS", "05_DIFFS", "06_LOGS", "07_ATTESTATIONS", "08_TAPES", "09_SCHEMAS", "12_REPORTS"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	receiptsDir := filepath.Join(dir, "02_PROOFGRAPH", "receipts")
	if err := os.MkdirAll(receiptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	receipt := []byte(`{"receipt_id":"rcpt-1","decision_id":"dec-1","decision_hash":"sha256:test","lamport_clock":1}`)
	if err := os.WriteFile(filepath.Join(receiptsDir, "receipt-1.json"), receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	scoreHash := sha256.Sum256(score)
	receiptHash := sha256.Sum256(receipt)
	entries := []map[string]string{
		{"path": "01_SCORE.json", "sha256": hex.EncodeToString(scoreHash[:])},
		{"path": "02_PROOFGRAPH/receipts/receipt-1.json", "sha256": hex.EncodeToString(receiptHash[:])},
	}
	for _, ext := range extensions {
		rel := "99_EXT/" + ext + "/proof.json"
		data := []byte(`{"ok":true}`)
		if err := os.MkdirAll(filepath.Join(dir, "99_EXT", ext), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, rel), data, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		entries = append(entries, map[string]string{"path": rel, "sha256": hex.EncodeToString(sum[:])})
	}
	index := map[string]any{
		"version": "1.0.0",
		"entries": entries,
	}
	if len(extensions) > 0 {
		index["extensions"] = extensions
	}
	indexData, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "00_INDEX.json"), append(indexData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := evidencepkg.SealEvidencePack(context.Background(), dir, evidencepkg.SealEvidencePackOptions{
		PackID:  "cli-sealed-pack",
		DataDir: dataDir,
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}
