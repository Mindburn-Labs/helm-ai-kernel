package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidencePackSealIndexRootEdgeCases(t *testing.T) {
	if _, err := ComputeEvidencePackIndexRoots(t.TempDir()); err == nil {
		t.Fatal("missing index should fail")
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "00_INDEX.json"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ComputeEvidencePackIndexRoots(dir); err == nil {
		t.Fatal("malformed index should fail")
	}

	validHash := strings.Repeat("a", 64)
	for name, entry := range map[string]indexRootEntry{
		"parent escape": {Path: "../escape", SHA256: validHash},
		"absolute path": {Path: filepath.Join(string(filepath.Separator), "escape"), SHA256: validHash},
		"bad hex":       {Path: "01_SCORE.json", SHA256: "not-hex"},
		"short digest":  {Path: "01_SCORE.json", SHA256: hex.EncodeToString([]byte{1, 2, 3})},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeRawSealIndex(t, dir, indexRootFile{Entries: []indexRootEntry{entry}})
			if _, err := ComputeEvidencePackIndexRoots(dir); err == nil {
				t.Fatal("invalid index entry should fail")
			}
		})
	}

	emptyDir := t.TempDir()
	writeRawSealIndex(t, emptyDir, indexRootFile{})
	roots, err := ComputeEvidencePackIndexRoots(emptyDir)
	if err != nil {
		t.Fatalf("empty index should compute an empty merkle root: %v", err)
	}
	if roots.EntryCount != 0 || roots.MerkleRoot != sha256HexEvidence(nil) {
		t.Fatalf("unexpected empty roots: %+v", roots)
	}
}

func TestVerifyEvidencePackIndexRootsChecksTheCompleteInventory(t *testing.T) {
	dir := t.TempDir()
	artifactPath := filepath.Join(dir, "01_SCORE.json")
	if err := os.WriteFile(artifactPath, []byte(`{"score":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSealTestIndex(t, dir, []string{"01_SCORE.json"})

	computed, err := ComputeEvidencePackIndexRoots(dir)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyEvidencePackIndexRoots(dir)
	if err != nil {
		t.Fatalf("verify indexed inventory: %v", err)
	}
	if verified != computed {
		t.Fatalf("verified roots=%+v, computed roots=%+v", verified, computed)
	}

	if err := os.WriteFile(artifactPath, []byte(`{"score":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEvidencePackIndexRoots(dir); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("tampered indexed file error=%v, want hash mismatch", err)
	}

	if err := os.WriteFile(artifactPath, []byte(`{"score":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "unindexed.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyEvidencePackIndexRoots(dir); err == nil || !strings.Contains(err.Error(), "unindexed evidence pack file") {
		t.Fatalf("unindexed file error=%v, want fail-closed rejection", err)
	}
}

func TestFileDevEvidenceSignerParseEdges(t *testing.T) {
	dir := t.TempDir()
	keyPath := FileDevEvidenceKeyPath(dir)
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileDevEvidenceSigner(dir); err == nil {
		t.Fatal("malformed file-dev key should fail")
	}

	keyFile := fileDevKeyFile{PrivateKey: "not-hex"}
	writeFileDevKey(t, keyPath, keyFile)
	if _, err := NewFileDevEvidenceSigner(dir); err == nil {
		t.Fatal("bad private key hex should fail")
	}

	keyFile.PrivateKey = hex.EncodeToString([]byte{1, 2, 3})
	writeFileDevKey(t, keyPath, keyFile)
	if _, err := NewFileDevEvidenceSigner(dir); err == nil {
		t.Fatal("short private key should fail")
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyFile = fileDevKeyFile{
		Version:    "file-dev-ed25519/v1",
		Algorithm:  "ed25519",
		KeyID:      "dev-key",
		PrivateKey: hex.EncodeToString(privateKey),
		PublicKey:  hex.EncodeToString(otherPublic),
	}
	writeFileDevKey(t, keyPath, keyFile)
	if _, err := NewFileDevEvidenceSigner(dir); err == nil {
		t.Fatal("mismatched file-dev public key should fail")
	}

	keyFile.KeyID = ""
	keyFile.PublicKey = hex.EncodeToString(publicKey)
	data, err := json.Marshal(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := parseFileDevEvidenceSigner("custom-key.json", data)
	if err != nil {
		t.Fatalf("key id fallback should parse: %v", err)
	}
	if !strings.HasPrefix(signer.KeyID(), "file-dev:") || signer.Path() != "custom-key.json" {
		t.Fatalf("unexpected parsed signer: key=%s path=%s", signer.KeyID(), signer.Path())
	}
}

func TestKMSEvidenceSignerAccessorsAndMismatchEdges(t *testing.T) {
	signer, err := NewKMSEvidenceSigner(EvidencePackTrustSigner{
		KMSKeyID:    "kms-key",
		PublicKey:   "public-key",
		SignCommand: `printf '{"key_id":"other-key","signature":"00"}'`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if signer.KeyID() != "kms-key" || signer.PublicKeyHex() != "public-key" || signer.SignerType() != "kms" {
		t.Fatalf("unexpected kms signer accessors: key=%s pub=%s type=%s", signer.KeyID(), signer.PublicKeyHex(), signer.SignerType())
	}
	if _, err := signer.Sign(context.Background(), []byte("payload")); err == nil || !strings.Contains(err.Error(), "key_id mismatch") {
		t.Fatalf("expected key id mismatch, got %v", err)
	}

	dynamic := &KMSEvidenceSigner{
		signCommand: `printf '{"key_id":"dynamic-key","public_key":"dynamic-public","signature":"00"}'`,
	}
	signature, err := dynamic.Sign(context.Background(), []byte("payload"))
	if err != nil {
		t.Fatalf("dynamic kms signer should adopt response metadata: %v", err)
	}
	if dynamic.KeyID() != "dynamic-key" || dynamic.PublicKeyHex() != "dynamic-public" || len(signature) != 1 {
		t.Fatalf("dynamic signer was not updated: key=%s pub=%s sig=%x", dynamic.KeyID(), dynamic.PublicKeyHex(), signature)
	}
}

func writeRawSealIndex(t *testing.T, dir string, index indexRootFile) {
	t.Helper()
	data, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "00_INDEX.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeFileDevKey(t *testing.T, path string, keyFile fileDevKeyFile) {
	t.Helper()
	data, err := json.Marshal(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
