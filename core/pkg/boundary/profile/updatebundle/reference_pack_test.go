package updatebundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
)

type updateBundleVectorFile struct {
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type updateBundleNegativeVector struct {
	ID            string `json:"id"`
	Mutation      string `json:"mutation"`
	ExpectedError string `json:"expected_error"`
}

type updateBundleVectorIndex struct {
	Comment         string                       `json:"$comment"`
	SchemaVersion   string                       `json:"schema_version"`
	QuantumPosture  string                       `json:"quantum_posture"`
	PublicKey       string                       `json:"public_key"`
	Manifest        updateBundleVectorFile       `json:"manifest"`
	SigningPayload  updateBundleVectorFile       `json:"signing_payload"`
	Signature       string                       `json:"signature"`
	Payloads        []updateBundleVectorFile     `json:"payloads"`
	NegativeVectors []updateBundleNegativeVector `json:"negative_vectors"`
}

func packSigner() *crypto.Ed25519Signer {
	return crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{79}, ed25519.SeedSize)), "update-bundle-vector",
	)
}

func packPayloads() map[string][]byte {
	return map[string][]byte{
		"policy_packs/soc2_type2.v1.json": []byte(`{"pack":"soc2_type2","version":1}` + "\n"),
		"notes/README.txt":                []byte("Offline update bundle golden payload. The tar.gz is reconstructed from these files by both verifiers.\n"),
	}
}

func canonicalFile(t *testing.T, v any) []byte {
	t.Helper()
	payload, err := canonicalize.JCS(v)
	if err != nil {
		t.Fatal(err)
	}
	return append(payload, '\n')
}

func buildUpdateBundleReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	payloads := packPayloads()
	paths := make([]string, 0, len(payloads))
	for path := range payloads {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	entries := make([]BundleEntry, 0, len(paths))
	for _, path := range paths {
		sum := sha256.Sum256(payloads[path])
		entries = append(entries, BundleEntry{Path: path, SHA256: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(payloads[path]))})
	}
	setHash, err := EntrySetHash(entries)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := SealManifest(UpdateBundleManifest{
		SchemaVersion:   UpdateBundleManifestSchemaVersion,
		BundleID:        "appliance-update-vector-01",
		KernelVersion:   "0.7.4",
		CreatedAt:       "2026-07-21T00:00:00Z",
		Entries:         entries,
		ArtifactSetHash: setHash,
		SignerKeyID:     "update-bundle-vector",
	}, packSigner())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := ManifestSigningBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{
		"manifest.c14n.json":                 canonicalFile(t, manifest),
		"manifest_signing_payload.c14n.json": append(payload, '\n'),
	}
	payloadVectors := make([]updateBundleVectorFile, 0, len(paths))
	for _, path := range paths {
		packPath := "payloads/" + path
		files[packPath] = payloads[path]
		payloadVectors = append(payloadVectors, updateBundleVectorFile{Canonical: packPath, SHA256: canonicalize.ComputeArtifactHash(payloads[path])})
	}
	// c14n vector pins hash the newline-stripped canonical text, matching the
	// shared load_canonical Python helper (payload pins stay full-byte).
	fileVector := func(name string) updateBundleVectorFile {
		return updateBundleVectorFile{Canonical: name, SHA256: canonicalize.ComputeArtifactHash(bytes.TrimSuffix(files[name], []byte("\n")))}
	}
	index := updateBundleVectorIndex{
		Comment:        "Offline update-bundle golden vectors: signed JCS manifest over a tar.gz payload set; format + verifier only (no build tooling, no OTA). Regenerate with UPDATE_UPDATE_BUNDLE_VECTORS=1 go test ./pkg/boundary/profile/updatebundle -run TestUpdateBundleReferencePackMatchesGoImplementation.",
		SchemaVersion:  "update_bundle_vectors.v1",
		QuantumPosture: "classical Ed25519 signatures only; no hybrid or post-quantum claim",
		PublicKey:      hex.EncodeToString(packSigner().PublicKeyBytes()),
		Manifest:       fileVector("manifest.c14n.json"),
		SigningPayload: fileVector("manifest_signing_payload.c14n.json"),
		Signature:      manifest.Signature,
		Payloads:       payloadVectors,
		NegativeVectors: []updateBundleNegativeVector{
			{ID: "signature_tamper", Mutation: "flip the final hex nibble of the manifest signature", ExpectedError: "signature_rejected"},
			{ID: "record_hash_tamper", Mutation: "replace manifest.record_hash with the hash of different bytes", ExpectedError: "hash_mismatch"},
			{ID: "entry_hash_flip", Mutation: "replace entries[0].sha256", ExpectedError: "set_hash_mismatch"},
			{ID: "payload_tamper", Mutation: "append one byte to payloads/notes/README.txt", ExpectedError: "payload_mismatch"},
			{ID: "size_lie", Mutation: "increment entries[0].size", ExpectedError: "set_hash_mismatch"},
			{ID: "kernel_version_substitution", Mutation: "set manifest.kernel_version to 9.9.9", ExpectedError: "hash_mismatch"},
		},
	}
	files["vectors.json"] = canonicalFile(t, index)

	type manifestEntry struct {
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
	}
	names := make([]string, 0, len(files))
	for name := range files {
		if name != "vectors.json" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	immutable := make([]manifestEntry, 0, len(names))
	for _, name := range names {
		immutable = append(immutable, manifestEntry{File: name, SHA256: canonicalize.HashBytes(files[name])})
	}
	files["SOURCE-MANIFEST.json"] = canonicalFile(t, map[string]any{
		"$comment":           "quantum_posture: classical_ed25519_only. Byte-exact payloads hash-pinned by vectors.json.",
		"source_repository":  "Mindburn-Labs/helm-ai-kernel",
		"source_path":        "reference_packs/update-bundle-v1",
		"pinning_authority":  "reference_packs/update-bundle-v1/vectors.json",
		"verifier":           "reference_packs/update-bundle-v1/verify_vectors.py",
		"immutable_payloads": immutable,
	})
	return files
}

func TestUpdateBundleReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildUpdateBundleReferencePack(t)
	root := filepath.Join("..", "..", "..", "..", "..", "reference_packs", "update-bundle-v1")
	if os.Getenv("UPDATE_UPDATE_BUNDLE_VECTORS") == "1" {
		for name, content := range files {
			target := filepath.Join(root, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, content, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s differs from the source-owned Go fixture; run UPDATE_UPDATE_BUNDLE_VECTORS=1 go test ./pkg/boundary/profile/updatebundle -run TestUpdateBundleReferencePackMatchesGoImplementation", name)
		}
	}

	// The reconstructed tar.gz must verify against the golden manifest —
	// same reconstruction the Python verifier documents.
	var manifest UpdateBundleManifest
	manifestBytes := bytes.TrimSuffix(files["manifest.c14n.json"], []byte("\n"))
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	bundle := buildTarGz(t, membersFor(packPayloads()))
	if err := VerifyBundle(bytes.NewReader(bundle), manifest, packSigner().PublicKeyBytes()); err != nil {
		t.Fatalf("reconstructed golden bundle must verify: %v", err)
	}
}
