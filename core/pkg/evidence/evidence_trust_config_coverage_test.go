package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	proofanchor "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/proofgraph/anchor"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

type fakeEvidenceAnchorBackend struct {
	err error
}

type fakeEvidenceBundleSigner struct {
	err error
}

func (b fakeEvidenceAnchorBackend) Name() string { return "fake" }

func (b fakeEvidenceAnchorBackend) Anchor(_ context.Context, req proofanchor.AnchorRequest) (*proofanchor.AnchorReceipt, error) {
	if b.err != nil {
		return nil, b.err
	}
	return &proofanchor.AnchorReceipt{
		Backend: "fake",
		Request: req,
		LogID:   "fake-log",
	}, nil
}

func (b fakeEvidenceAnchorBackend) Verify(context.Context, *proofanchor.AnchorReceipt) error {
	return b.err
}

func (s fakeEvidenceBundleSigner) Sign([]byte) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	return "sig", nil
}

func (s fakeEvidenceBundleSigner) PublicKey() string { return "pub" }

func TestEvidenceTrustConfigRoundTripsAndDefaults(t *testing.T) {
	dataDir := t.TempDir()
	cfg, err := NewEvidencePackTrustConfig("", "", "", "", false, dataDir)
	if err != nil {
		t.Fatalf("NewEvidencePackTrustConfig default: %v", err)
	}
	if cfg.ActiveProfile != EvidenceTrustProfileDevLocal || cfg.Signer.Type != "file-dev" {
		t.Fatalf("unexpected default config: %+v", cfg)
	}
	if cfg.Anchor.Status != "development-only" || cfg.Storage.Status != "development-only" {
		t.Fatalf("local trust defaults not marked development-only: %+v", cfg)
	}
	if cfg.Signer.KeyID == "" || cfg.Signer.PublicKey == "" || cfg.TrustedKeys[cfg.Signer.KeyID] == "" {
		t.Fatalf("file-dev signer was not bound into trusted keys: %+v", cfg)
	}

	defaultPath := EvidencePackTrustConfigPath(dataDir)
	if !strings.HasSuffix(defaultPath, filepath.Join("trust", "evidence-pack.json")) {
		t.Fatalf("default trust config path = %s", defaultPath)
	}
	if EvidencePackTrustConfigPathForWrite(" explicit.json ", dataDir) != "explicit.json" {
		t.Fatal("explicit config path was not trimmed")
	}

	path, err := SaveEvidencePackTrustConfig(dataDir, cfg)
	if err != nil {
		t.Fatalf("SaveEvidencePackTrustConfig: %v", err)
	}
	loaded, err := LoadEvidencePackTrustConfig(dataDir)
	if err != nil {
		t.Fatalf("LoadEvidencePackTrustConfig: %v", err)
	}
	if loaded == nil || loaded.Signer.KeyID != cfg.Signer.KeyID {
		t.Fatalf("loaded config = %+v, want signer %s", loaded, cfg.Signer.KeyID)
	}

	t.Setenv("HELM_EVIDENCE_TRUST_CONFIG", path)
	if EvidencePackTrustConfigPath("ignored") != path {
		t.Fatal("trust config env override was not used")
	}
	loaded, err = LoadEvidencePackTrustConfigWithPath("", "ignored")
	if err != nil || loaded == nil || loaded.Signer.KeyID != cfg.Signer.KeyID {
		t.Fatalf("env-loaded config = %+v err=%v", loaded, err)
	}
	t.Setenv("HELM_EVIDENCE_TRUST_CONFIG", "")

	yamlPath := filepath.Join(t.TempDir(), "trust.yaml")
	yamlCfg := cfg
	yamlCfg.ActiveProfile = EvidenceTrustProfileTeam
	yamlCfg.Anchor = EvidencePackSealAnchor{Type: "rekor", URL: "https://rekor.example"}
	yamlCfg.Storage = EvidencePackSealStorage{Type: "s3-object-lock", Bucket: "audit-bucket", ObjectLock: true}
	if _, err := SaveEvidencePackTrustConfigWithPath(yamlPath, "", yamlCfg); err != nil {
		t.Fatalf("SaveEvidencePackTrustConfigWithPath yaml: %v", err)
	}
	loadedYAML, err := LoadEvidencePackTrustConfigWithPath(yamlPath, "")
	if err != nil {
		t.Fatalf("LoadEvidencePackTrustConfigWithPath yaml: %v", err)
	}
	if loadedYAML.ActiveProfile != EvidenceTrustProfileTeam || loadedYAML.Anchor.Type != "rekor" {
		t.Fatalf("loaded yaml config = %+v", loadedYAML)
	}

	nestedProfileOnly := filepath.Join(t.TempDir(), "profile-only.yaml")
	if err := os.WriteFile(nestedProfileOnly, []byte("trust:\n  evidence_pack:\n    profile: customer\n    signer:\n      type: kms\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loadedNested, err := LoadEvidencePackTrustConfigWithPath(nestedProfileOnly, "")
	if err != nil {
		t.Fatalf("load nested profile config: %v", err)
	}
	if loadedNested.ActiveProfile != EvidenceTrustProfileCustomer {
		t.Fatalf("nested profile was not normalized: %+v", loadedNested)
	}
}

func TestEvidenceTrustConfigKMSAndHelperBranches(t *testing.T) {
	_, publicKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HELM_EVIDENCE_KMS_KEY_ID", "kms-key")
	t.Setenv("HELM_EVIDENCE_KMS_PUBLIC_KEY_HEX", hex.EncodeToString(publicKey))
	t.Setenv("HELM_EVIDENCE_KMS_SIGN_COMMAND", "unused-command")

	cfg, err := NewEvidencePackTrustConfig(EvidenceTrustProfileCustomer, "kms", "rekor", "s3-object-lock", true, "")
	if err != nil {
		t.Fatalf("NewEvidencePackTrustConfig kms: %v", err)
	}
	if cfg.Signer.KeyID != "kms-key" || cfg.Signer.KMSKeyID != "kms-key" || cfg.TrustedKeys["kms-key"] == "" {
		t.Fatalf("kms config did not bind env signer fields: %+v", cfg)
	}
	if cfg.Anchor.Status != "configured" || cfg.Storage.Status != "configured" || !cfg.Storage.Immutable {
		t.Fatalf("external trust statuses not configured: %+v", cfg)
	}

	if _, err := NewEvidencePackTrustConfig(EvidenceTrustProfileTeam, "unsupported", "", "", false, ""); err == nil {
		t.Fatal("unsupported signer should fail closed")
	}
	if !ProfileRequiresExternalTrust(EvidenceTrustProfileCustomer) || !ProfileRequiresExternalTrust("prod") {
		t.Fatal("customer/prod profiles should require external trust")
	}
	if ProfileRequiresExternalTrust(EvidenceTrustProfileTeam) {
		t.Fatal("team profile should not require external trust")
	}
	if got := BuildEvidencePackVerifyCommand("bundle.tar", EvidenceTrustProfileCustomer, "storage.json"); !strings.Contains(got, "--profile customer") || !strings.Contains(got, "--storage-receipt storage.json") {
		t.Fatalf("customer verify command missing flags: %s", got)
	}
	if got := BuildEvidencePackVerifyCommand("bundle.tar", EvidenceTrustProfileTeam, "storage.json"); strings.Contains(got, "--profile") {
		t.Fatalf("team verify command should stay local: %s", got)
	}
	if !isLocalEvidenceSignerType(" Local-Dev ") || isLocalEvidenceSignerType("kms") {
		t.Fatal("local signer type classification failed")
	}
	if statusForTrustType("rekor") != "configured" || statusForTrustType("") != "development-only" {
		t.Fatal("trust status mapping failed")
	}

	t.Setenv("HELM_DATA_DIR", filepath.Join(t.TempDir(), "env-data"))
	if ResolveEvidencePackDataDir("") != os.Getenv("HELM_DATA_DIR") {
		t.Fatal("HELM_DATA_DIR was not used")
	}
	if ResolveEvidencePackDataDir(" explicit-data ") != "explicit-data" {
		t.Fatal("explicit evidence data dir was not trimmed")
	}
}

func TestEvidenceSealValidationAndKeyEdges(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyHex := hex.EncodeToString(publicKey)
	seal := EvidencePackSeal{
		Signer: EvidencePackSealSigner{
			Type:      "kms",
			KeyID:     "kms-key",
			PublicKey: publicKeyHex,
		},
		Anchor:  EvidencePackSealAnchor{Type: "rekor"},
		Storage: EvidencePackSealStorage{Type: "s3-object-lock", ObjectLock: true},
	}

	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", publicKeyHex)
	trusted, err := trustedPublicKeyForSeal(seal, nil, EvidenceTrustProfileTeam)
	if err != nil {
		t.Fatalf("trusted key env fallback: %v", err)
	}
	if !strings.EqualFold(hex.EncodeToString(trusted), publicKeyHex) {
		t.Fatalf("trusted key = %x, want %s", trusted, publicKeyHex)
	}
	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", strings.Repeat("0", ed25519.PublicKeySize*2))
	if _, err := trustedPublicKeyForSeal(seal, nil, EvidenceTrustProfileTeam); err == nil {
		t.Fatal("trusted key mismatch should fail")
	}

	if _, err := decodeEd25519PublicKey("not-hex"); err == nil {
		t.Fatal("invalid public key hex should fail")
	}
	if _, err := decodeEd25519PublicKey(hex.EncodeToString([]byte{1})); err == nil {
		t.Fatal("short public key should fail")
	}

	if errs := validateProfileSeal(EvidencePackSeal{Signer: EvidencePackSealSigner{Type: "file-dev"}}, nil, EvidenceTrustProfileTeam); len(errs) == 0 || !strings.Contains(strings.Join(errs, "; "), "signer key id") {
		t.Fatalf("team profile key-id errors = %v", errs)
	}
	t.Setenv("HELM_EVIDENCE_TRUSTED_PUBLIC_KEY_HEX", "")
	customerErrs := validateProfileSeal(EvidencePackSeal{
		Signer:  EvidencePackSealSigner{Type: "file-dev"},
		Anchor:  EvidencePackSealAnchor{Type: "local-dev"},
		Storage: EvidencePackSealStorage{Type: "local-dev"},
	}, nil, EvidenceTrustProfileCustomer)
	joined := strings.Join(customerErrs, "; ")
	if !strings.Contains(joined, "external signer") || !strings.Contains(joined, "external anchor") || !strings.Contains(joined, "off-host storage") || !strings.Contains(joined, "local trust config") {
		t.Fatalf("customer profile errors = %v", customerErrs)
	}
	highErrs := validateProfileSeal(EvidencePackSeal{
		Signer:  EvidencePackSealSigner{Type: "kms", KeyID: "kms-key"},
		Anchor:  EvidencePackSealAnchor{Type: "rekor"},
		Storage: EvidencePackSealStorage{Type: "s3-object-lock"},
	}, &EvidencePackTrustConfig{}, EvidenceTrustProfileHighAssurance)
	if !strings.Contains(strings.Join(highErrs, "; "), "immutable/WORM") {
		t.Fatalf("high-assurance profile errors = %v", highErrs)
	}
	if errs := validateProfileSeal(EvidencePackSeal{}, nil, "mystery"); len(errs) == 0 || !strings.Contains(errs[0], "unknown evidence trust profile") {
		t.Fatalf("unknown profile errors = %v", errs)
	}

	if merkleRootHexEvidence(nil) != sha256HexEvidence(nil) {
		t.Fatal("empty evidence merkle root should be sha256(nil)")
	}
	if root := merkleRootHexEvidence([][]byte{[]byte("a"), []byte("b"), []byte("c")}); root == "" || len(root) != 64 {
		t.Fatalf("odd-leaf evidence merkle root = %q", root)
	}
}

func TestEvidenceAnchorAndStorageEdges(t *testing.T) {
	ctx := context.Background()
	root := strings.Repeat("a", 64)

	receipts, err := anchorEvidenceRoot(ctx, fakeEvidenceAnchorBackend{}, root)
	if err != nil {
		t.Fatalf("anchorEvidenceRoot: %v", err)
	}
	if len(receipts) != 1 || receipts[0].Request.MerkleRoot != root || receipts[0].Request.HeadNodeIDs[0] != root {
		t.Fatalf("unexpected anchor receipts: %+v", receipts)
	}
	if _, err := anchorEvidenceRoot(ctx, fakeEvidenceAnchorBackend{err: errors.New("anchor failed")}, root); err == nil {
		t.Fatal("anchor backend failure should propagate")
	}

	receipts, err = createEvidenceAnchorReceipts(ctx, root, nil, EvidencePackSealAnchor{Type: "local-dev"})
	if err != nil || receipts != nil {
		t.Fatalf("local-dev anchor should not create receipts: receipts=%v err=%v", receipts, err)
	}
	if _, err := createEvidenceAnchorReceipts(ctx, root, nil, EvidencePackSealAnchor{Type: "rfc3161"}); err == nil {
		t.Fatal("rfc3161 without URL should fail")
	}
	if _, err := createEvidenceAnchorReceipts(ctx, root, nil, EvidencePackSealAnchor{Type: "unknown"}); err == nil {
		t.Fatal("unknown anchor type should fail")
	}
	if anchorEndpoint(EvidencePackSealAnchor{URI: "anchor://explicit"}, nil) != "anchor://explicit" {
		t.Fatal("explicit anchor URI was not preferred")
	}
	if anchorEndpoint(EvidencePackSealAnchor{}, &EvidencePackTrustConfig{Anchor: EvidencePackSealAnchor{URL: "https://cfg.example"}}) != "https://cfg.example" {
		t.Fatal("config anchor URL was not used")
	}

	status, errs := verifyEvidenceAnchorReceipts(ctx, EvidencePackSeal{}, nil, EvidenceTrustProfileTeam)
	if status != "local-only" || len(errs) != 0 {
		t.Fatalf("team no-anchor status=%s errs=%v", status, errs)
	}
	status, errs = verifyEvidenceAnchorReceipts(ctx, EvidencePackSeal{}, nil, EvidenceTrustProfileCustomer)
	if status != "missing" || len(errs) == 0 {
		t.Fatalf("customer no-anchor status=%s errs=%v", status, errs)
	}
	status, errs = verifyEvidenceAnchorReceipts(ctx, EvidencePackSeal{
		MerkleRoot: root,
		AnchorReceipts: []proofanchor.AnchorReceipt{{
			Backend: "fake",
			Request: proofanchor.AnchorRequest{MerkleRoot: "other"},
		}},
	}, nil, EvidenceTrustProfileCustomer)
	if status != "invalid" || !strings.Contains(strings.Join(errs, "; "), "subject root mismatch") {
		t.Fatalf("mismatched anchor status=%s errs=%v", status, errs)
	}
	status, errs = verifyEvidenceAnchorReceipts(ctx, EvidencePackSeal{
		MerkleRoot: root,
		AnchorReceipts: []proofanchor.AnchorReceipt{{
			Backend: "fake",
			Request: proofanchor.AnchorRequest{MerkleRoot: root},
		}},
	}, nil, EvidenceTrustProfileCustomer)
	if status != "invalid" || !strings.Contains(strings.Join(errs, "; "), "unsupported anchor backend") {
		t.Fatalf("unsupported anchor status=%s errs=%v", status, errs)
	}

	if DefaultStorageReceiptPath("bundle.tar") != "bundle.tar.storage.json" {
		t.Fatal("default storage receipt path changed")
	}
	if err := WriteStorageReceipt("", EvidencePackStorageReceipt{}); err == nil {
		t.Fatal("empty storage receipt path should fail")
	}
	badReceiptPath := filepath.Join(t.TempDir(), "bad-storage.json")
	if err := os.WriteFile(badReceiptPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadStorageReceipt(badReceiptPath); err == nil {
		t.Fatal("invalid storage receipt JSON should fail")
	}
	now := fixedSealTime()
	statusStorage, _, storageErrs := VerifyStorageReceiptForSeal(EvidencePackSeal{}, EvidenceTrustProfileDevLocal, "", "", now)
	if statusStorage != "local-only" || len(storageErrs) != 0 {
		t.Fatalf("dev-local storage status=%s errs=%v", statusStorage, storageErrs)
	}
	statusStorage, _, storageErrs = VerifyStorageReceiptForSeal(EvidencePackSeal{}, EvidenceTrustProfileCustomer, "", "", now)
	if statusStorage != "missing" || len(storageErrs) == 0 {
		t.Fatalf("customer missing storage status=%s errs=%v", statusStorage, storageErrs)
	}

	receiptPath := filepath.Join(t.TempDir(), "storage.json")
	if err := WriteStorageReceipt(receiptPath, EvidencePackStorageReceipt{
		SchemaVersion: "bad",
		StorageType:   "mutable",
		SubjectRoot:   "wrong",
		Bucket:        "other-bucket",
		ObjectHash:    "not-a-sha",
		RetentionMode: "GOVERNANCE",
		RetainUntil:   now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	statusStorage, _, storageErrs = VerifyStorageReceiptForSeal(EvidencePackSeal{
		MerkleRoot: root,
		Storage:    EvidencePackSealStorage{Bucket: "expected-bucket"},
	}, EvidenceTrustProfileCustomer, receiptPath, "", now)
	joinedStorage := strings.Join(storageErrs, "; ")
	if statusStorage != "invalid" ||
		!strings.Contains(joinedStorage, "unsupported storage receipt schema") ||
		!strings.Contains(joinedStorage, "unsupported storage receipt type") ||
		!strings.Contains(joinedStorage, "subject root mismatch") ||
		!strings.Contains(joinedStorage, "missing bucket, key, or version_id") ||
		!strings.Contains(joinedStorage, "object_hash") ||
		!strings.Contains(joinedStorage, "bucket does not match") {
		t.Fatalf("invalid storage status=%s errs=%v", statusStorage, storageErrs)
	}
}

func TestEnvelopeExportErrorAndPayloadBranches(t *testing.T) {
	now := fixedSealTime()
	if _, err := BuildEnvelopeManifest(EnvelopeExportRequest{
		NativeEvidenceHash: "sha256:root",
		CreatedAt:          now,
	}); err == nil {
		t.Fatal("missing envelope type should fail")
	}
	if _, err := BuildEnvelopeManifest(EnvelopeExportRequest{
		Envelope:           EnvelopeDSSE,
		NativeEvidenceHash: "sha256:root",
		Statement:          map[string]any{"bad": func() {}},
		CreatedAt:          now,
	}); err == nil {
		t.Fatal("non-canonical statement should fail")
	}
	if _, err := BuildEnvelopePayload(contracts.EvidenceEnvelopeManifest{}); err == nil {
		t.Fatal("missing payload envelope should fail")
	}

	for _, envelope := range []EnvelopeExportType{EnvelopeInToto, EnvelopeSLSA, EnvelopeSigstore, EnvelopeCOSE} {
		manifest, err := BuildEnvelopeManifest(EnvelopeExportRequest{
			ManifestID:         "manifest-" + string(envelope),
			Envelope:           envelope,
			NativeEvidenceHash: "sha256:root",
			Subject:            "pack:subject",
			CreatedAt:          now,
			AllowExperimental:  true,
		})
		if err != nil {
			t.Fatalf("BuildEnvelopeManifest(%s): %v", envelope, err)
		}
		payload, err := BuildEnvelopePayload(manifest)
		if err != nil {
			t.Fatalf("BuildEnvelopePayload(%s): %v", envelope, err)
		}
		if payload.PayloadType != payloadTypeForEnvelope(envelope) {
			t.Fatalf("%s payload type = %s", envelope, payload.PayloadType)
		}
		if payload.Authoritative {
			t.Fatalf("%s payload should be non-authoritative", envelope)
		}
	}

	manifest, err := BuildEnvelopeManifest(EnvelopeExportRequest{
		ManifestID:         "manifest-verify",
		Envelope:           EnvelopeDSSE,
		NativeEvidenceHash: "sha256:root",
		Subject:            "pack:subject",
		CreatedAt:          now,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := BuildEnvelopePayload(manifest)
	if err != nil {
		t.Fatal(err)
	}
	payload.Authoritative = true
	result := VerifyEnvelopePayload(manifest, payload)
	if result.Verified || result.Checks["envelope_role"] != "FAIL" {
		t.Fatalf("authoritative external payload should fail: %+v", result)
	}

	payload.Authoritative = false
	payload.Payload = map[string]any{"bad": func() {}}
	result = VerifyEnvelopePayload(manifest, payload)
	if result.Verified || result.Checks["payload_hash"] != "FAIL" {
		t.Fatalf("non-canonical payload content should fail: %+v", result)
	}

	badManifest := manifest
	badManifest.NativeAuthority = false
	badManifest.NativeEvidenceHash = ""
	badManifest.ManifestHash = "sha256:not-the-hash"
	result = VerifyEnvelopePayload(badManifest, payload)
	if result.Verified ||
		result.Checks["native_authority"] != "FAIL" ||
		result.Checks["manifest_hash"] != "FAIL" ||
		result.Checks["payload_hash"] != "FAIL" {
		t.Fatalf("bad manifest checks = %+v", result.Checks)
	}
}

func TestEvidenceExporterFailClosedBranches(t *testing.T) {
	if _, err := NewExporter(nil, "key").ExportSOC2(context.Background(), "trace", nil); err == nil {
		t.Fatal("SOC2 export without signer should fail closed")
	}
	if _, err := NewExporter(fakeEvidenceBundleSigner{}, "").ExportIncidentReport(context.Background(), "trace", map[string]string{}); err == nil {
		t.Fatal("incident export without key id should fail closed")
	}
	if _, err := NewExporter(fakeEvidenceBundleSigner{err: errors.New("sign failed")}, "key").ExportIncidentReport(context.Background(), "trace", map[string]string{"error": "timeout"}); err == nil {
		t.Fatal("signer failure should fail export")
	}

	bundle := &Bundle{
		ID:        "bundle",
		Type:      BundleTypeSOC2,
		TraceID:   "trace",
		Timestamp: fixedSealTime(),
		Artifacts: []Artifact{
			{Name: "z", Hash: "sha256:z"},
			{Name: "a", Hash: "sha256:a"},
		},
	}
	if err := sealBundle(bundle, fakeEvidenceBundleSigner{}); err != nil {
		t.Fatalf("sealBundle: %v", err)
	}
	if bundle.Artifacts[0].Name != "a" || bundle.Signature == "" || bundle.BundleHash == "" {
		t.Fatalf("bundle was not sorted and sealed: %+v", bundle)
	}
}

func TestStoreArchiveWithS3ObjectLockFailClosedBranches(t *testing.T) {
	ctx := context.Background()
	if _, err := StoreArchiveWithS3ObjectLock(ctx, "missing.tar", "root", EvidencePackSealStorage{}); err == nil {
		t.Fatal("missing S3 bucket should fail")
	}
	if _, err := StoreArchiveWithS3ObjectLock(ctx, "missing.tar", "root", EvidencePackSealStorage{
		Bucket:         "bucket",
		ObjectLockMode: "GOVERNANCE",
	}); err == nil || !strings.Contains(err.Error(), "COMPLIANCE") {
		t.Fatalf("non-COMPLIANCE mode should fail, got %v", err)
	}
	if _, err := StoreArchiveWithS3ObjectLock(ctx, filepath.Join(t.TempDir(), "missing.tar"), "root", EvidencePackSealStorage{
		Bucket: "bucket",
	}); err == nil {
		t.Fatal("missing archive should fail before AWS config")
	}

	archivePath := filepath.Join(t.TempDir(), "pack.tar")
	if err := os.WriteFile(archivePath, []byte("archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalLoader := loadS3ObjectLockConfig
	loadS3ObjectLockConfig = func(context.Context, ...func(*config.LoadOptions) error) (aws.Config, error) {
		return aws.Config{}, errors.New("config unavailable")
	}
	t.Cleanup(func() { loadS3ObjectLockConfig = originalLoader })
	if _, err := StoreArchiveWithS3ObjectLock(ctx, archivePath, "root", EvidencePackSealStorage{
		Bucket:        "bucket",
		Region:        "eu-test-1",
		RetentionDays: 7,
		Prefix:        "/packs",
	}); err == nil || !strings.Contains(err.Error(), "load AWS config") {
		t.Fatalf("AWS config load failure should propagate, got %v", err)
	}
}
