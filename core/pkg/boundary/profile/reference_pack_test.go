package profile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

type boundaryProfileVectorFile struct {
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type boundaryProfileSignedVector struct {
	Artifact       boundaryProfileVectorFile `json:"artifact"`
	SigningPayload boundaryProfileVectorFile `json:"signing_payload"`
	PublicKey      string                    `json:"public_key"`
	Signature      string                    `json:"signature"`
}

type boundaryProfileArtifactVector struct {
	Path      string `json:"path"`
	Canonical string `json:"canonical"`
	SHA256    string `json:"sha256"`
}

type boundaryProfileNegativeVector struct {
	ID            string `json:"id"`
	Mutation      string `json:"mutation"`
	ExpectedError string `json:"expected_error"`
}

type boundaryProfileVectorIndex struct {
	Comment          string                          `json:"$comment"`
	SchemaVersion    string                          `json:"schema_version"`
	QuantumPosture   string                          `json:"quantum_posture"`
	ProfileInput     boundaryProfileVectorFile       `json:"profile_input"`
	CompileReceipt   boundaryProfileSignedVector     `json:"compile_receipt"`
	AttestationMatch boundaryProfileSignedVector     `json:"attestation_match"`
	AttestationDrift boundaryProfileVectorFile       `json:"attestation_drift"`
	Artifacts        []boundaryProfileArtifactVector `json:"artifacts"`
	NegativeVectors  []boundaryProfileNegativeVector `json:"negative_vectors"`
}

// packInput is the vector-pack input, deliberately separate from
// fixtureInput so unit-test tweaks never silently rewrite golden vectors.
func packInput() ProfileInput {
	return ProfileInput{
		SchemaVersion: ProfileInputSchemaVersion,
		ProfileID:     "appliance-vector-01",
		ModeTier:      TierEnforce,
		Topology: Topology{
			GatewayUnit:   "helm-gateway.service",
			WorkloadUnits: []string{"orchestrator.service"},
			Gateway:       GatewayEndpoint{Kind: "tcp", Address: "127.0.0.1:7714"},
		},
		Egress: firewall.EgressPolicy{
			AllowedDomains:   []string{"api.example.com"},
			AllowedCIDRs:     []string{"203.0.113.0/24"},
			AllowedProtocols: []string{"https"},
			MaxPayloadBytes:  1048576,
		},
		Resources:     sandbox.ResourceLimits{CPUMillis: 500, MemoryMB: 512, MaxProcesses: 128},
		Hardening:     DefaultHardening(),
		DevicePermits: []string{"/dev/null rw"},
	}
}

func packSigner() *crypto.Ed25519Signer {
	return crypto.NewEd25519SignerFromKey(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{73}, ed25519.SeedSize)), "boundary-profile-vector",
	)
}

func canonicalFile(t *testing.T, v any) []byte {
	t.Helper()
	payload, err := canonicalize.JCS(v)
	if err != nil {
		t.Fatal(err)
	}
	return append(payload, '\n')
}

func buildBoundaryProfileReferencePack(t *testing.T) map[string][]byte {
	t.Helper()
	signer := packSigner()
	input := packInput()
	compiled, err := Compile(input, signer, CompileOptions{
		KernelVersion: "0.7.4",
		CompiledAt:    time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	posture := mustExpectedPosture(t, compiled)

	healthy := proberFromExpected(posture, string(compiled.Files[nftFilePath]))
	match, err := Attest(compiled.Receipt, compiled.Files, healthy, signer, AttestOptions{
		ObservedAt: time.Date(2026, 7, 21, 0, 5, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	drifted := proberFromExpected(posture, string(compiled.Files[nftFilePath]))
	base := drifted.SystemdProps
	drifted.SystemdProps = func(unit string, props []string) (map[string]string, error) {
		values, err := base(unit, props)
		if err != nil {
			return nil, err
		}
		if unit == "helm-gateway.service" {
			values["NoNewPrivileges"] = "no"
		}
		return values, nil
	}
	// The DRIFT vector is hash-sealed but unsigned: the wire form of an
	// appliance without a configured attestation signer.
	drift, err := Attest(compiled.Receipt, compiled.Files, drifted, nil, AttestOptions{
		ObservedAt: time.Date(2026, 7, 21, 0, 10, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{
		"profile_input.c14n.json":     canonicalFile(t, input),
		"compile_receipt.c14n.json":   canonicalFile(t, compiled.Receipt),
		"attestation_match.c14n.json": canonicalFile(t, match),
		"attestation_drift.c14n.json": canonicalFile(t, drift),
	}
	receiptPayload, err := CompileReceiptSigningBytes(compiled.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	files["compile_receipt_signing_payload.c14n.json"] = append(receiptPayload, '\n')
	matchPayload, err := PostureAttestationSigningBytes(match)
	if err != nil {
		t.Fatal(err)
	}
	files["attestation_match_signing_payload.c14n.json"] = append(matchPayload, '\n')

	artifactPaths := make([]string, 0, len(compiled.Files))
	for path := range compiled.Files {
		artifactPaths = append(artifactPaths, path)
	}
	sort.Strings(artifactPaths)
	artifactVectors := make([]boundaryProfileArtifactVector, 0, len(artifactPaths))
	for _, path := range artifactPaths {
		packPath := "artifacts/" + path
		files[packPath] = compiled.Files[path]
		artifactVectors = append(artifactVectors, boundaryProfileArtifactVector{
			Path:      path,
			Canonical: packPath,
			SHA256:    canonicalize.ComputeArtifactHash(compiled.Files[path]),
		})
	}

	// c14n vector pins hash the newline-stripped canonical text, matching the
	// shared load_canonical Python helper (raw artifact pins stay full-byte).
	fileVector := func(name string) boundaryProfileVectorFile {
		return boundaryProfileVectorFile{Canonical: name, SHA256: canonicalize.ComputeArtifactHash(bytes.TrimSuffix(files[name], []byte("\n")))}
	}
	publicKey := hex.EncodeToString(packSigner().PublicKeyBytes())
	index := boundaryProfileVectorIndex{
		Comment:        "Boundary Enforcement Profile golden vectors: HELM compiles OS enforcement artifacts and attests posture; the OS enforces. Regenerate with UPDATE_BOUNDARY_PROFILE_VECTORS=1 go test ./pkg/boundary/profile -run TestBoundaryProfileReferencePackMatchesGoImplementation.",
		SchemaVersion:  "boundary_profile_vectors.v1",
		QuantumPosture: "classical Ed25519 signatures only; no hybrid or post-quantum claim",
		ProfileInput:   fileVector("profile_input.c14n.json"),
		CompileReceipt: boundaryProfileSignedVector{
			Artifact:       fileVector("compile_receipt.c14n.json"),
			SigningPayload: fileVector("compile_receipt_signing_payload.c14n.json"),
			PublicKey:      publicKey,
			Signature:      compiled.Receipt.Signature,
		},
		AttestationMatch: boundaryProfileSignedVector{
			Artifact:       fileVector("attestation_match.c14n.json"),
			SigningPayload: fileVector("attestation_match_signing_payload.c14n.json"),
			PublicKey:      publicKey,
			Signature:      match.Signature,
		},
		AttestationDrift: fileVector("attestation_drift.c14n.json"),
		Artifacts:        artifactVectors,
		NegativeVectors: []boundaryProfileNegativeVector{
			{ID: "signature_tamper", Mutation: "flip the final hex nibble of compile_receipt.signature", ExpectedError: "signature_rejected"},
			{ID: "record_hash_tamper", Mutation: "replace compile_receipt.record_hash with the hash of different bytes", ExpectedError: "hash_mismatch"},
			{ID: "tier_substitution", Mutation: "set compile_receipt.mode_tier to observe", ExpectedError: "hash_mismatch"},
			{ID: "artifact_set_substitution", Mutation: "replace compile_receipt.artifact_set_hash", ExpectedError: "hash_mismatch"},
			{ID: "artifact_content_tamper", Mutation: "append one byte to artifacts/nftables/helm-boundary.nft", ExpectedError: "artifact_mismatch"},
			{ID: "input_substitution", Mutation: "set profile_input.mode_tier to observe", ExpectedError: "input_hash_mismatch"},
			{ID: "drift_reported_as_match", Mutation: "set attestation_drift.verdict to MATCH", ExpectedError: "verdict_inconsistent"},
			{ID: "attestation_receipt_unbound", Mutation: "replace attestation_match.receipt_hash", ExpectedError: "binding_mismatch"},
		},
	}
	files["vectors.json"] = canonicalFile(t, index)

	type manifestEntry struct {
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
	}
	manifestNames := make([]string, 0, len(files))
	for name := range files {
		if name != "vectors.json" {
			manifestNames = append(manifestNames, name)
		}
	}
	sort.Strings(manifestNames)
	entries := make([]manifestEntry, 0, len(manifestNames))
	for _, name := range manifestNames {
		entries = append(entries, manifestEntry{File: name, SHA256: canonicalize.HashBytes(files[name])})
	}
	files["SOURCE-MANIFEST.json"] = canonicalFile(t, map[string]any{
		"$comment":           "quantum_posture: classical_ed25519_only. Byte-exact canonical payloads hash-pinned by vectors.json; they cannot host inline annotations without invalidating signatures/digests, so this manifest carries the posture note.",
		"source_repository":  "Mindburn-Labs/helm-ai-kernel",
		"source_path":        "reference_packs/boundary-profile-v1",
		"pinning_authority":  "reference_packs/boundary-profile-v1/vectors.json",
		"verifier":           "reference_packs/boundary-profile-v1/verify_vectors.py",
		"immutable_payloads": entries,
	})
	return files
}

func TestBoundaryProfileReferencePackMatchesGoImplementation(t *testing.T) {
	files := buildBoundaryProfileReferencePack(t)
	root := filepath.Join("..", "..", "..", "..", "reference_packs", "boundary-profile-v1")
	if os.Getenv("UPDATE_BOUNDARY_PROFILE_VECTORS") == "1" {
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
			t.Fatalf("%s differs from the source-owned Go fixture; run UPDATE_BOUNDARY_PROFILE_VECTORS=1 go test ./pkg/boundary/profile -run TestBoundaryProfileReferencePackMatchesGoImplementation", name)
		}
	}
}
