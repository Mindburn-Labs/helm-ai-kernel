package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/profile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/boundary/profile/updatebundle"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/canonicalize"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/crypto"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/firewall"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/sandbox"
)

const boundaryTestSeedHex = "0707070707070707070707070707070707070707070707070707070707070707"

func boundaryTestPublicKeyHex() string {
	seed, _ := hex.DecodeString(boundaryTestSeedHex)
	return hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

func writeBoundaryProfileInput(t *testing.T, dir string) string {
	t.Helper()
	input := profile.ProfileInput{
		SchemaVersion: profile.ProfileInputSchemaVersion,
		ProfileID:     "cli-test-01",
		ModeTier:      profile.TierEnforce,
		Topology: profile.Topology{
			GatewayUnit:   "helm-gateway.service",
			WorkloadUnits: []string{"orchestrator.service"},
			Gateway:       profile.GatewayEndpoint{Kind: "tcp", Address: "127.0.0.1:7714"},
		},
		Egress: firewall.EgressPolicy{
			AllowedCIDRs:     []string{"203.0.113.0/24"},
			AllowedProtocols: []string{"https"},
		},
		Resources: sandbox.ResourceLimits{CPUMillis: 500, MemoryMB: 512, MaxProcesses: 128},
		Hardening: profile.DefaultHardening(),
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "profile_input.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestBoundaryProfileCompileVerifyFlow(t *testing.T) {
	t.Setenv("HELM_SIGNING_KEY_HEX", boundaryTestSeedHex)
	dir := t.TempDir()
	inputPath := writeBoundaryProfileInput(t, dir)
	outDir := filepath.Join(dir, "profile")

	var stdout, stderr bytes.Buffer
	code := runBoundaryProfileCmd([]string{"compile", "--input", inputPath, "--out", outDir,
		"--kernel-version", "0.7.4-test", "--compiled-at", "2026-07-21T00:00:00Z"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("compile exit %d: %s", code, stderr.String())
	}
	for _, want := range []string{
		"compile_receipt.json",
		"systemd/helm-gateway.service.d/50-helm-boundary.conf",
		"systemd/orchestrator.service.d/50-helm-boundary.conf",
		"nftables/helm-boundary.nft",
		"posture/expected_posture.json",
	} {
		if _, err := os.Stat(filepath.Join(outDir, filepath.FromSlash(want))); err != nil {
			t.Fatalf("compile must write %s: %v", want, err)
		}
	}

	stdout.Reset()
	stderr.Reset()
	code = runBoundaryProfileCmd([]string{"verify",
		"--receipt", filepath.Join(outDir, "compile_receipt.json"),
		"--artifacts", outDir,
		"--public-key", boundaryTestPublicKeyHex()}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("verify exit %d: %s%s", code, stdout.String(), stderr.String())
	}

	// Offline verify must fail closed under the wrong trust root.
	wrongKey := strings.Repeat("00", ed25519.PublicKeySize)
	stdout.Reset()
	stderr.Reset()
	if code := runBoundaryProfileCmd([]string{"verify",
		"--receipt", filepath.Join(outDir, "compile_receipt.json"),
		"--public-key", wrongKey}, &stdout, &stderr); code != 1 {
		t.Fatalf("verify under wrong key must exit 1, got %d", code)
	}
}

func TestBoundaryProfileCompileRequiresSigningKey(t *testing.T) {
	t.Setenv("HELM_SIGNING_KEY_HEX", "")
	dir := t.TempDir()
	inputPath := writeBoundaryProfileInput(t, dir)
	var stdout, stderr bytes.Buffer
	code := runBoundaryProfileCmd([]string{"compile", "--input", inputPath, "--out", filepath.Join(dir, "out")}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("unsigned compile must exit 2, got %d", code)
	}
	if !strings.Contains(stderr.String(), "never emitted unsigned") {
		t.Fatalf("stderr must state the no-unsigned-receipts rule: %s", stderr.String())
	}
}

// TestBoundaryProfileAttestEnforceFailsClosedOffAppliance asserts the
// ExecCondition/oneshot contract: on any box whose live posture cannot be
// read or does not match (this test host is not the appliance), attest
// --enforce exits non-zero and records the attestation.
func TestBoundaryProfileAttestEnforceFailsClosedOffAppliance(t *testing.T) {
	t.Setenv("HELM_SIGNING_KEY_HEX", boundaryTestSeedHex)
	dir := t.TempDir()
	inputPath := writeBoundaryProfileInput(t, dir)
	outDir := filepath.Join(dir, "profile")
	var stdout, stderr bytes.Buffer
	if code := runBoundaryProfileCmd([]string{"compile", "--input", inputPath, "--out", outDir,
		"--kernel-version", "0.7.4-test", "--compiled-at", "2026-07-21T00:00:00Z"}, &stdout, &stderr); code != 0 {
		t.Fatalf("compile exit %d: %s", code, stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code := runBoundaryProfileCmd([]string{"attest",
		"--receipt", filepath.Join(outDir, "compile_receipt.json"),
		"--artifacts", outDir,
		"--out", filepath.Join(dir, "attestation.json"),
		"--observed-at", "2026-07-21T00:05:00Z",
		"--enforce"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("attest --enforce must fail closed off-appliance; stdout: %s", stdout.String())
	}
}

func TestBoundaryProfileAttestTamperedArtifactsHardError(t *testing.T) {
	t.Setenv("HELM_SIGNING_KEY_HEX", boundaryTestSeedHex)
	dir := t.TempDir()
	inputPath := writeBoundaryProfileInput(t, dir)
	outDir := filepath.Join(dir, "profile")
	var stdout, stderr bytes.Buffer
	if code := runBoundaryProfileCmd([]string{"compile", "--input", inputPath, "--out", outDir,
		"--kernel-version", "0.7.4-test", "--compiled-at", "2026-07-21T00:00:00Z"}, &stdout, &stderr); code != 0 {
		t.Fatalf("compile exit %d: %s", code, stderr.String())
	}
	nftPath := filepath.Join(outDir, "nftables", "helm-boundary.nft")
	loosened, err := os.ReadFile(nftPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nftPath, append(loosened, []byte("# loosened\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code := runBoundaryProfileCmd([]string{"attest",
		"--receipt", filepath.Join(outDir, "compile_receipt.json"),
		"--artifacts", outDir,
		"--observed-at", "2026-07-21T00:05:00Z"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("tampered artifacts must exit 1 even without --enforce, got %d", code)
	}
	if !strings.Contains(stderr.String(), "modified after compile") {
		t.Fatalf("stderr must name the tamper: %s", stderr.String())
	}
}

func TestBoundaryProfileBundleVerifyCLI(t *testing.T) {
	dir := t.TempDir()
	payload := []byte(`{"pack":"soc2_type2","version":1}` + "\n")
	sum := sha256.Sum256(payload)
	entries := []updatebundle.BundleEntry{{
		Path:   "policy_packs/soc2_type2.v1.json",
		SHA256: "sha256:" + hex.EncodeToString(sum[:]),
		Size:   int64(len(payload)),
	}}
	setHash, err := updatebundle.EntrySetHash(entries)
	if err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(boundaryTestSeedHex)
	signer := crypto.NewEd25519SignerFromKey(ed25519.NewKeyFromSeed(seed), "bundle-key")
	manifest, err := updatebundle.SealManifest(updatebundle.UpdateBundleManifest{
		SchemaVersion:   updatebundle.UpdateBundleManifestSchemaVersion,
		BundleID:        "bundle-cli-test",
		KernelVersion:   "0.7.4-test",
		CreatedAt:       "2026-07-21T00:00:00Z",
		Entries:         entries,
		ArtifactSetHash: setHash,
		SignerKeyID:     "bundle-key",
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := canonicalize.JCS(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: entries[0].Path, Mode: 0o644, Size: entries[0].Size, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(dir, "bundle.tar.gz")
	if err := os.WriteFile(bundlePath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := runBoundaryProfileCmd([]string{"bundle-verify",
		"--bundle", bundlePath, "--manifest", manifestPath,
		"--public-key", boundaryTestPublicKeyHex()}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("bundle-verify exit %d: %s", code, stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := runBoundaryProfileCmd([]string{"bundle-verify",
		"--bundle", bundlePath, "--manifest", manifestPath,
		"--public-key", strings.Repeat("00", ed25519.PublicKeySize)}, &stdout, &stderr); code != 1 {
		t.Fatalf("bundle-verify under wrong key must exit 1, got %d", code)
	}
}

func TestBoundaryProfileUsageExits(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := runBoundaryProfileCmd(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("no subcommand must exit 2, got %d", code)
	}
	if code := runBoundaryProfileCmd([]string{"unknown"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown subcommand must exit 2, got %d", code)
	}
	stdout.Reset()
	if code := runBoundaryProfileCmd([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("--help must exit 0, got %d", code)
	}
	if !strings.Contains(stdout.String(), "the OS enforces") {
		t.Fatalf("usage must state the doctrine: %s", stdout.String())
	}
	if code := runBoundarySurfaceCmd([]string{"profile", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("boundary profile --help via the surface command must exit 0, got %d", code)
	}
}
