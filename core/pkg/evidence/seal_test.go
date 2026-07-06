package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	proofanchor "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph/anchor"
)

// quantum_posture: tests exercise classical Ed25519 seal and receipt paths only;
// they do not assert post-quantum signature resistance.
func TestExternalSignerHelper(t *testing.T) {
	if os.Getenv("HELM_TEST_EXTERNAL_SIGNER") != "1" {
		return
	}
	var req crypto.ExternalSignRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintln(os.Stdout, `{"signature":""}`)
		os.Exit(0)
	}
	payload, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		fmt.Fprintln(os.Stdout, `{"signature":""}`)
		os.Exit(0)
	}
	privateBytes, err := hex.DecodeString(os.Getenv("HELM_TEST_EXTERNAL_SIGNER_PRIVATE"))
	if err != nil {
		fmt.Fprintln(os.Stdout, `{"signature":""}`)
		os.Exit(0)
	}
	privateKey := ed25519.PrivateKey(privateBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	resp := crypto.ExternalSignResponse{
		Algorithm: "ed25519",
		KeyID:     req.KeyID,
		PublicKey: hex.EncodeToString(publicKey),
		Signature: hex.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
	_ = json.NewEncoder(os.Stdout).Encode(resp)
	os.Exit(0)
}

func TestSealEvidencePackCreatesValidSeal(t *testing.T) {
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json": []byte(`{"pass":true}`),
	})
	seal, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{
		PackID:   "pack-test",
		DataDir:  t.TempDir(),
		SignedAt: fixedSealTime(),
	})
	if err != nil {
		t.Fatalf("SealEvidencePack: %v", err)
	}
	if seal.Signature == "" {
		t.Fatal("seal signature missing")
	}
	if _, err := os.Stat(filepath.Join(packDir, EvidencePackSealPath)); err != nil {
		t.Fatalf("seal file missing: %v", err)
	}
	result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{Profile: EvidenceTrustProfileDevLocal})
	if result.State != "valid" || !result.SignatureValid {
		t.Fatalf("seal did not verify: %+v", result)
	}
}

func TestSealEvidencePackCanonicalPayloadIsStable(t *testing.T) {
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json": []byte(`{"pass":true}`),
	})
	seal, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{
		PackID:   "pack-stable",
		DataDir:  t.TempDir(),
		SignedAt: fixedSealTime(),
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := canonicalSealPayload(*seal)
	if err != nil {
		t.Fatal(err)
	}
	second, err := canonicalSealPayload(*seal)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatalf("canonical payload changed:\n%s\n%s", first, second)
	}
	if strings.Contains(string(first), "signature") {
		t.Fatalf("signature must not be part of signed payload: %s", first)
	}
}

func TestVerifyEvidencePackSealRejectsBadSignature(t *testing.T) {
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json": []byte(`{"pass":true}`),
	})
	if _, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{DataDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(packDir, EvidencePackSealPath)
	var seal EvidencePackSeal
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &seal); err != nil {
		t.Fatal(err)
	}
	seal.Signature = strings.Repeat("0", ed25519.SignatureSize*2)
	data, _ = json.MarshalIndent(seal, "", "  ")
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{Profile: EvidenceTrustProfileDevLocal})
	if result.State == "valid" || result.SignatureValid {
		t.Fatalf("bad signature verified: %+v", result)
	}
}

func TestVerifyEvidencePackSealRejectsBadTrustedKey(t *testing.T) {
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json": []byte(`{"pass":true}`),
	})
	seal, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &EvidencePackTrustConfig{
		ActiveProfile: EvidenceTrustProfileDevLocal,
		TrustedKeys: map[string]string{
			seal.Signer.KeyID: hex.EncodeToString(wrongPub),
		},
	}
	result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{
		Profile:     EvidenceTrustProfileDevLocal,
		TrustConfig: cfg,
	})
	if result.State == "valid" {
		t.Fatalf("wrong trusted key accepted: %+v", result)
	}
}

func TestTeamProfileAllowsLocalAnchorAndStorageWithoutReceipts(t *testing.T) {
	dataDir := t.TempDir()
	signer, err := NewFileDevEvidenceSigner(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json": []byte(`{"pass":true}`),
	})
	cfg := &EvidencePackTrustConfig{
		Version:       "evidence-pack-trust/v1",
		ActiveProfile: EvidenceTrustProfileTeam,
		Signer: EvidencePackTrustSigner{
			Type:      "file-dev",
			KeyID:     signer.KeyID(),
			PublicKey: signer.PublicKeyHex(),
		},
		Anchor: EvidencePackSealAnchor{Type: "local-dev", Status: "local-only"},
		Storage: EvidencePackSealStorage{
			Type:   "local-dev",
			Status: "local-only",
		},
		TrustedKeys: map[string]string{signer.KeyID(): signer.PublicKeyHex()},
		UpdatedAt:   fixedSealTime(),
	}
	if _, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{
		PackID:      "team-pack",
		Profile:     EvidenceTrustProfileTeam,
		Signer:      signer,
		TrustConfig: cfg,
		SignedAt:    fixedSealTime(),
	}); err != nil {
		t.Fatal(err)
	}
	result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{
		Profile:     EvidenceTrustProfileTeam,
		TrustConfig: cfg,
		Now:         fixedSealTime(),
	})
	if result.State != "valid" || !result.SignatureValid {
		t.Fatalf("team seal did not verify: %+v", result)
	}
	if result.AnchorStatus != "local-only" || result.StorageStatus != "local-only" {
		t.Fatalf("team seal required external receipts: %+v", result)
	}
	if joined := strings.Join(result.Errors, "; "); strings.Contains(joined, "requires external") || strings.Contains(joined, "requires storage receipt") {
		t.Fatalf("team seal reported customer-grade receipt requirements: %s", joined)
	}
}

func TestVerifyEvidencePackSealTeamAcceptsTrustedKeyEnvWithoutCustomerArtifacts(t *testing.T) {
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json": []byte(`{"pass":true}`),
	})
	dataDir := t.TempDir()
	signer, err := NewFileDevEvidenceSigner(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &EvidencePackTrustConfig{
		ActiveProfile: EvidenceTrustProfileTeam,
		Signer: EvidencePackTrustSigner{
			Type:      "file-dev",
			KeyID:     signer.KeyID(),
			PublicKey: signer.PublicKeyHex(),
		},
		Anchor:      EvidencePackSealAnchor{Type: "local-dev", Status: "development-only"},
		Storage:     EvidencePackSealStorage{Type: "local-dev", Status: "development-only"},
		TrustedKeys: map[string]string{signer.KeyID(): signer.PublicKeyHex()},
	}
	if _, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{
		PackID:      "team-pack",
		Profile:     EvidenceTrustProfileTeam,
		Signer:      signer,
		TrustConfig: cfg,
		SignedAt:    fixedSealTime(),
	}); err != nil {
		t.Fatalf("SealEvidencePack: %v", err)
	}

	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", signer.PublicKeyHex())
	result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{
		Profile: EvidenceTrustProfileTeam,
		DataDir: t.TempDir(),
		Now:     fixedSealTime(),
	})
	if result.State != "valid" || !result.SignatureValid {
		t.Fatalf("team seal did not verify with trusted-key env: %+v", result)
	}
	if result.AnchorStatus != "local-only" || result.StorageStatus != "local-only" {
		t.Fatalf("team seal should not require customer artifacts: %+v", result)
	}
}

func TestLoadEvidencePackTrustConfigSkipsImplicitUnrelatedHelmYAML(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(cwd)
	})
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("helm", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("helm", "helm.yaml"), []byte("project:\n  name: unrelated\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadEvidencePackTrustConfigWithPath("", filepath.Join(dir, "data"))
	if err != nil {
		t.Fatalf("implicit unrelated helm.yaml should be skipped: %v", err)
	}
	if cfg != nil {
		t.Fatalf("unexpected trust config from unrelated helm.yaml: %+v", cfg)
	}

	_, err = LoadEvidencePackTrustConfigWithPath(filepath.Join("helm", "helm.yaml"), filepath.Join(dir, "data"))
	if err == nil {
		t.Fatal("explicit unrelated trust config path should fail closed")
	}
}

func TestSealEvidencePackKMSConfigFailsClosedWhenUnconfigured(t *testing.T) {
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json": []byte(`{"pass":true}`),
	})
	cfg := &EvidencePackTrustConfig{
		ActiveProfile: EvidenceTrustProfileCustomer,
		Signer:        EvidencePackTrustSigner{Type: "kms"},
		Anchor:        EvidencePackSealAnchor{Type: "ledger", Status: "configured"},
		Storage:       EvidencePackSealStorage{Type: "s3", Status: "configured"},
	}
	_, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{TrustConfig: cfg})
	if err == nil || !strings.Contains(err.Error(), "kms evidence signer is not configured") {
		t.Fatalf("expected unconfigured kms fail-closed error, got %v", err)
	}
}

func TestFileDevSignerPersistsKeyMaterial(t *testing.T) {
	dataDir := t.TempDir()
	first, err := NewFileDevEvidenceSigner(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewFileDevEvidenceSigner(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyID() != second.KeyID() || first.PublicKeyHex() != second.PublicKeyHex() {
		t.Fatalf("file-dev key was not persisted: %s/%s", first.KeyID(), second.KeyID())
	}
	if _, err := os.Stat(FileDevEvidenceKeyPath(dataDir)); err != nil {
		t.Fatalf("key file missing: %v", err)
	}
}

func TestVerifyEvidencePackSealRejectsRegeneratedIndexWithOldSeal(t *testing.T) {
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json": []byte(`{"pass":true}`),
	})
	if _, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{DataDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "01_SCORE.json"), []byte(`{"pass":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSealTestIndex(t, packDir, []string{"01_SCORE.json"})
	result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{Profile: EvidenceTrustProfileDevLocal})
	if result.State == "valid" {
		t.Fatalf("old seal accepted after index regeneration: %+v", result)
	}
	if !strings.Contains(strings.Join(result.Errors, "; "), "index_hash mismatch") {
		t.Fatalf("expected index_hash mismatch, got %+v", result.Errors)
	}
}

func TestVerifyEvidencePackSealRejectsIndexedFileTamper(t *testing.T) {
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json": []byte(`{"pass":true}`),
	})
	if _, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{DataDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "01_SCORE.json"), []byte(`{"pass":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{Profile: EvidenceTrustProfileDevLocal})
	if result.State == "valid" {
		t.Fatalf("tampered indexed file accepted: %+v", result)
	}
	if !strings.Contains(strings.Join(result.Errors, "; "), "indexed file hash mismatch") {
		t.Fatalf("expected indexed file hash mismatch, got %+v", result.Errors)
	}
}

func TestVerifyEvidencePackSealRejectsUnindexedExtensionFile(t *testing.T) {
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json":                       []byte(`{"pass":true}`),
		"99_EXT/helm-formal-proof/proof.json": []byte(`{"ok":true}`),
	})
	writeSealTestIndexWithExtensions(t, packDir, []string{"01_SCORE.json"}, []string{"helm-formal-proof"})
	if _, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{DataDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{Profile: EvidenceTrustProfileDevLocal})
	if result.State == "valid" {
		t.Fatalf("unindexed extension file accepted: %+v", result)
	}
	if !strings.Contains(strings.Join(result.Errors, "; "), "unindexed evidence pack file: 99_EXT/helm-formal-proof/proof.json") {
		t.Fatalf("expected unindexed extension failure, got %+v", result.Errors)
	}
}

func TestVerifyEvidencePackSealRejectsUnindexedEvidenceFile(t *testing.T) {
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json": []byte(`{"pass":true}`),
	})
	if _, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{DataDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(packDir, "06_PROOFGRAPH"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packDir, "06_PROOFGRAPH", "unindexed.json"), []byte(`{"extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{Profile: EvidenceTrustProfileDevLocal})
	if result.State == "valid" {
		t.Fatalf("unindexed evidence file accepted: %+v", result)
	}
	if !strings.Contains(strings.Join(result.Errors, "; "), "unindexed evidence pack file: 06_PROOFGRAPH/unindexed.json") {
		t.Fatalf("expected unindexed evidence file failure, got %+v", result.Errors)
	}
}

func TestVerifyEvidencePackSealRejectsUnindexedConformanceSignature(t *testing.T) {
	packDir := writeSealTestPack(t, map[string][]byte{
		"01_SCORE.json": []byte(`{"pass":true}`),
	})
	if _, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{DataDir: t.TempDir()}); err != nil {
		t.Fatal(err)
	}
	attestDir := filepath.Join(packDir, "07_ATTESTATIONS")
	if err := os.MkdirAll(attestDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(attestDir, "conformance_report.sig"), []byte("unsigned-test-fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{Profile: EvidenceTrustProfileDevLocal})
	if result.State == "valid" {
		t.Fatalf("unindexed conformance signature accepted: %+v", result)
	}
	if !strings.Contains(strings.Join(result.Errors, "; "), "unindexed evidence pack file: 07_ATTESTATIONS/conformance_report.sig") {
		t.Fatalf("expected unindexed conformance signature failure, got %+v", result.Errors)
	}
}

func TestVerifyStorageReceiptForSealRequiresCustomerGradeS3(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "pack.tar")
	if err := os.WriteFile(archivePath, []byte("sealed archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	objectHash, err := HashFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	seal := EvidencePackSeal{
		MerkleRoot: "root-1",
		Storage:    EvidencePackSealStorage{Type: "s3", Bucket: "audit-bucket"},
	}
	receipt := EvidencePackStorageReceipt{
		SchemaVersion: EvidencePackStorageReceiptSchemaS3,
		StorageType:   "s3-object-lock",
		SubjectRoot:   seal.MerkleRoot,
		Bucket:        "audit-bucket",
		Key:           "packs/root-1.tar",
		Region:        "us-east-1",
		VersionID:     "version-1",
		ObjectHash:    objectHash,
		RetentionMode: "COMPLIANCE",
		RetainUntil:   fixedSealTime().Add(24 * time.Hour),
		StoredAt:      fixedSealTime(),
	}
	receiptPath := filepath.Join(t.TempDir(), "storage.json")
	if err := WriteStorageReceipt(receiptPath, receipt); err != nil {
		t.Fatal(err)
	}
	status, path, errs := VerifyStorageReceiptForSeal(seal, EvidenceTrustProfileCustomer, receiptPath, archivePath, fixedSealTime())
	if status != "immutable-off-host" || path != receiptPath || len(errs) != 0 {
		t.Fatalf("valid storage receipt rejected: status=%s path=%s errs=%v", status, path, errs)
	}

	receipt.RetentionMode = "GOVERNANCE"
	if err := WriteStorageReceipt(receiptPath, receipt); err != nil {
		t.Fatal(err)
	}
	status, _, errs = VerifyStorageReceiptForSeal(seal, EvidenceTrustProfileCustomer, receiptPath, archivePath, fixedSealTime())
	if status != "invalid" || !strings.Contains(strings.Join(errs, "; "), "COMPLIANCE") {
		t.Fatalf("non-COMPLIANCE receipt was not rejected: status=%s errs=%v", status, errs)
	}

	receipt.RetentionMode = "COMPLIANCE"
	receipt.RetainUntil = fixedSealTime().Add(-time.Hour)
	if err := WriteStorageReceipt(receiptPath, receipt); err != nil {
		t.Fatal(err)
	}
	status, _, errs = VerifyStorageReceiptForSeal(seal, EvidenceTrustProfileCustomer, receiptPath, archivePath, fixedSealTime())
	if status != "invalid" || !strings.Contains(strings.Join(errs, "; "), "retention is not active") {
		t.Fatalf("expired retention was not rejected: status=%s errs=%v", status, errs)
	}
}

func TestVerifyStorageReceiptForSealRejectsHashAndSubjectMismatch(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "pack.tar")
	if err := os.WriteFile(archivePath, []byte("actual archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	seal := EvidencePackSeal{MerkleRoot: "root-1", Storage: EvidencePackSealStorage{Type: "s3"}}
	receipt := EvidencePackStorageReceipt{
		SchemaVersion: EvidencePackStorageReceiptSchemaS3,
		StorageType:   "s3-object-lock",
		SubjectRoot:   "other-root",
		Bucket:        "bucket",
		Key:           "key",
		VersionID:     "version",
		ObjectHash:    "sha256:" + strings.Repeat("0", 64),
		RetentionMode: "COMPLIANCE",
		RetainUntil:   fixedSealTime().Add(time.Hour),
		StoredAt:      fixedSealTime(),
	}
	receiptPath := filepath.Join(t.TempDir(), "storage.json")
	if err := WriteStorageReceipt(receiptPath, receipt); err != nil {
		t.Fatal(err)
	}
	status, _, errs := VerifyStorageReceiptForSeal(seal, EvidenceTrustProfileCustomer, receiptPath, archivePath, fixedSealTime())
	joined := strings.Join(errs, "; ")
	if status != "invalid" || !strings.Contains(joined, "subject root mismatch") || !strings.Contains(joined, "object_hash mismatch") {
		t.Fatalf("expected subject/hash failures, status=%s errs=%v", status, errs)
	}
}

func TestVerifyEvidenceAnchorReceiptsAcceptsRFC3161AndRekorFakes(t *testing.T) {
	root := strings.Repeat("a", 64)
	token, err := asn1.Marshal(1)
	if err != nil {
		t.Fatal(err)
	}
	rfcSeal := EvidencePackSeal{
		MerkleRoot: root,
		AnchorReceipts: []proofanchor.AnchorReceipt{{
			Backend:   "rfc3161",
			Request:   proofanchor.AnchorRequest{MerkleRoot: root},
			LogID:     "http://tsa.example",
			Signature: base64.StdEncoding.EncodeToString(token),
		}},
	}
	status, errs := verifyEvidenceAnchorReceipts(context.Background(), rfcSeal, &EvidencePackTrustConfig{
		Anchor: EvidencePackSealAnchor{Type: "rfc3161", URI: "http://tsa.example"},
	}, EvidenceTrustProfileCustomer)
	if status != "verified-externally" || len(errs) != 0 {
		t.Fatalf("rfc3161 receipt rejected: status=%s errs=%v", status, errs)
	}

	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/log/entries" || r.URL.Query().Get("logIndex") != "7" {
			t.Fatalf("unexpected Rekor request: %s", r.URL.String())
		}
		fmt.Fprint(w, `{"uuid":{"logID":"rekor-log","logIndex":7,"integratedTime":1}}`)
	}))
	defer rekor.Close()
	rekorSeal := EvidencePackSeal{
		MerkleRoot: root,
		AnchorReceipts: []proofanchor.AnchorReceipt{{
			Backend:  "rekor-v2",
			Request:  proofanchor.AnchorRequest{MerkleRoot: root},
			LogID:    "rekor-log",
			LogIndex: 7,
		}},
	}
	status, errs = verifyEvidenceAnchorReceipts(context.Background(), rekorSeal, &EvidencePackTrustConfig{
		Anchor: EvidencePackSealAnchor{Type: "rekor", URI: rekor.URL},
	}, EvidenceTrustProfileCustomer)
	if status != "verified-externally" || len(errs) != 0 {
		t.Fatalf("rekor receipt rejected: status=%s errs=%v", status, errs)
	}
}

func TestKMSEvidenceSignerUsesJSONExternalSignerProtocol(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_TEST_EXTERNAL_SIGNER", "1")
	t.Setenv("HELM_TEST_EXTERNAL_SIGNER_PRIVATE", hex.EncodeToString(privateKey))
	command := fmt.Sprintf("%q -test.run=TestExternalSignerHelper --", os.Args[0])
	signer, err := NewKMSEvidenceSigner(EvidencePackTrustSigner{
		KeyID:       "kms-key",
		SignCommand: command,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("payload")
	signature, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		t.Fatal("external signer signature did not verify")
	}
	if signer.PublicKeyHex() != hex.EncodeToString(publicKey) {
		t.Fatalf("signer did not capture public key: %s", signer.PublicKeyHex())
	}
}

func TestKMSEvidenceSignerRejectsMalformedExternalSignerOutput(t *testing.T) {
	signer, err := NewKMSEvidenceSigner(EvidencePackTrustSigner{
		KeyID:       "kms-key",
		SignCommand: "printf not-json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(context.Background(), []byte("payload")); err == nil {
		t.Fatal("malformed signer output was accepted")
	}
}

func BenchmarkVerifyEvidencePackSeal(b *testing.B) {
	files := make(map[string][]byte, 129)
	files["01_SCORE.json"] = []byte(`{"pass":true}`)
	payload := strings.Repeat("0123456789abcdef", 256)
	for i := 0; i < 128; i++ {
		files[fmt.Sprintf("04_ARTIFACTS/file-%03d.json", i)] = []byte(fmt.Sprintf(`{"id":%d,"payload":%q}`, i, payload))
	}
	packDir := writeSealTestPack(b, files)
	if _, err := SealEvidencePack(context.Background(), packDir, SealEvidencePackOptions{
		DataDir:  b.TempDir(),
		SignedAt: fixedSealTime(),
	}); err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := VerifyEvidencePackSeal(packDir, VerifyEvidencePackSealOptions{Profile: EvidenceTrustProfileDevLocal})
		if result.State != "valid" || !result.SignatureValid {
			b.Fatalf("seal did not verify: %+v", result)
		}
	}
}

func writeSealTestPack(t testing.TB, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for rel, data := range files {
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "07_ATTESTATIONS"), 0o700); err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(files))
	for rel := range files {
		paths = append(paths, rel)
	}
	writeSealTestIndex(t, dir, paths)
	return dir
}

func writeSealTestIndex(t testing.TB, dir string, paths []string) {
	writeSealTestIndexWithExtensions(t, dir, paths, nil)
}

func writeSealTestIndexWithExtensions(t testing.TB, dir string, paths []string, extensions []string) {
	t.Helper()
	entries := make([]map[string]string, 0, len(paths))
	for _, rel := range paths {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		entries = append(entries, map[string]string{"path": rel, "sha256": hex.EncodeToString(sum[:])})
	}
	index := map[string]any{"version": "1.0.0", "entries": entries}
	if len(extensions) > 0 {
		index["extensions"] = extensions
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "00_INDEX.json"), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func fixedSealTime() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}
