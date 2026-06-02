package gates

import (
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/conform"
)

func TestG0BuildIdentityEvidenceDirectoryFallbacks(t *testing.T) {
	_, ctx := setupG0(t)
	attestDir := filepath.Join(ctx.EvidenceDir, "07_ATTESTATIONS")

	writeGateFile(t, filepath.Join(ctx.ProjectRoot, "go.sum"), []byte("dep-lock"))
	writeGateFile(t, filepath.Join(attestDir, "build_identity.json"), []byte(`{"version":"1.0"}`))
	writeGateFile(t, filepath.Join(attestDir, "sbom.xml"), []byte(`<sbom/>`))
	writeGateFile(t, filepath.Join(attestDir, "provenance.jsonl"), []byte(`{"predicate":{}}`))
	writeGateFile(t, filepath.Join(attestDir, "signing_keys.json"), []byte(`{"keys":[]}`))

	result := (&G0BuildIdentity{}).Run(ctx)
	if !result.Pass {
		t.Fatalf("evidence fallback artifacts should pass: %+v", result)
	}
	if result.Metrics.Counts["build_identity"] != 1 ||
		result.Metrics.Counts["dep_locks"] != 1 ||
		result.Metrics.Counts["trust_roots"] != 1 {
		t.Fatalf("unexpected metrics: %+v", result.Metrics.Counts)
	}
}

func TestG0BuildIdentityInvalidAndMissingBuildIdentity(t *testing.T) {
	_, invalidCtx := setupG0(t)
	writeG0RequiredArtifactsExceptBuildIdentity(t, invalidCtx)
	writeGateFile(t, filepath.Join(invalidCtx.ProjectRoot, "artifacts", "build_identity.json"), []byte("{"))

	result := (&G0BuildIdentity{}).Run(invalidCtx)
	if result.Pass || !reasonContains(result.Reasons, conform.ReasonBuildIdentityMissing) {
		t.Fatalf("invalid build identity result = %+v, want build identity failure", result)
	}

	_, missingCtx := setupG0(t)
	writeG0RequiredArtifactsExceptBuildIdentity(t, missingCtx)
	result = (&G0BuildIdentity{}).Run(missingCtx)
	if result.Pass || !reasonContains(result.Reasons, conform.ReasonBuildIdentityMissing) {
		t.Fatalf("missing build identity result = %+v, want build identity failure", result)
	}
}

func TestG0BuildIdentityHelperReadErrors(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	if err := validateBuildIdentity(missing); err == nil {
		t.Fatal("validateBuildIdentity should fail for a missing file")
	}

	dst := filepath.Join(t.TempDir(), "copied.json")
	copyToEvidence(missing, dst)
	if fileExists(dst) {
		t.Fatalf("copyToEvidence created destination for missing source: %s", dst)
	}
}

func writeG0RequiredArtifactsExceptBuildIdentity(t *testing.T, ctx *conform.RunContext) {
	t.Helper()

	writeGateFile(t, filepath.Join(ctx.ProjectRoot, "go.sum"), []byte("dep-lock"))
	writeGateFile(t, filepath.Join(ctx.ProjectRoot, "artifacts", "sbom.json"), []byte(`{"components":[]}`))
	writeGateFile(t, filepath.Join(ctx.ProjectRoot, "artifacts", "provenance.json"), []byte(`{"predicate":{}}`))
	writeGateFile(t, filepath.Join(ctx.ProjectRoot, "artifacts", "trust_roots.json"), []byte(`{"keys":[]}`))
}
