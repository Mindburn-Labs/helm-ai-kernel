package gates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
	"github.com/stretchr/testify/require"
)

func setupG0(t *testing.T) (string, *conform.RunContext) {
	t.Helper()
	dir := t.TempDir()
	projRoot := filepath.Join(dir, "project")
	evidenceDir := filepath.Join(dir, "evidence")
	require.NoError(t, conform.CreateEvidencePackDirs(evidenceDir))
	require.NoError(t, os.MkdirAll(filepath.Join(projRoot, "artifacts"), 0750))

	ctx := &conform.RunContext{
		RunID:       "test-run",
		Profile:     conform.ProfileCore,
		EvidenceDir: evidenceDir,
		ProjectRoot: projRoot,
	}
	return dir, ctx
}

func TestG0_SBOMPresent(t *testing.T) {
	dir, ctx := setupG0(t)

	// Create all required files
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "go.sum"), []byte("dep-lock"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "build_identity.json"), []byte(`{"version":"1.0"}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "sbom.json"), []byte(`{"components":[]}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "provenance.json"), []byte(`{"predicate":{}}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "trust_roots.json"), []byte(`{"keys":[]}`), 0600))
	_ = dir

	gate := &G0BuildIdentity{}
	require.NotEmpty(t, gate.Name())
	result := gate.Run(ctx)
	require.True(t, result.Pass, "all artifacts present: %v", result.Reasons)
}

func TestG0_SBOMAbsent(t *testing.T) {
	_, ctx := setupG0(t)

	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "go.sum"), []byte("dep-lock"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "build_identity.json"), []byte(`{"version":"1.0"}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "provenance.json"), []byte(`{"predicate":{}}`), 0600))
	// No SBOM

	gate := &G0BuildIdentity{}
	result := gate.Run(ctx)
	require.False(t, result.Pass)
	require.Contains(t, result.Reasons, conform.ReasonBuildIdentityMissing)
}

func TestG0_ProvenanceMissing(t *testing.T) {
	_, ctx := setupG0(t)

	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "go.sum"), []byte("dep-lock"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "build_identity.json"), []byte(`{"version":"1.0"}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "sbom.json"), []byte(`{}`), 0600))
	// No provenance

	gate := &G0BuildIdentity{}
	result := gate.Run(ctx)
	require.False(t, result.Pass, "missing provenance must fail")
}

func TestG0_BuildMetadataValid(t *testing.T) {
	_, ctx := setupG0(t)

	validJSON := `{"version":"1.0","build_time":"2026-02-13T12:00:00Z","commit":"abc123"}`
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "build_identity.json"), []byte(validJSON), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "go.sum"), []byte("x"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "sbom.json"), []byte(`{}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "provenance.json"), []byte(`{}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "trust_roots.json"), []byte(`{"keys":[]}`), 0600))

	gate := &G0BuildIdentity{}
	result := gate.Run(ctx)
	require.True(t, result.Pass)
}

func TestG0_DependencyLocksMissing(t *testing.T) {
	_, ctx := setupG0(t)

	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "build_identity.json"), []byte(`{}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "sbom.json"), []byte(`{}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(ctx.ProjectRoot, "artifacts", "provenance.json"), []byte(`{}`), 0600))
	// No go.sum

	gate := &G0BuildIdentity{}
	result := gate.Run(ctx)
	require.False(t, result.Pass)
	require.Contains(t, result.Reasons, conform.ReasonBuildIdentityMissing)
}
