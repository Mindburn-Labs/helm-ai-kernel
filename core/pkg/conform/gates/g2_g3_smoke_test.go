package gates

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/conform"
	"github.com/stretchr/testify/require"
)

func setupGateCtx(t *testing.T) *conform.RunContext {
	t.Helper()

	dir := t.TempDir()
	evidenceDir := filepath.Join(dir, "evidence")
	require.NoError(t, conform.CreateEvidencePackDirs(evidenceDir))

	projectRoot := filepath.Join(dir, "project")
	require.NoError(t, os.MkdirAll(projectRoot, 0750))

	return &conform.RunContext{
		RunID:       "test-run",
		Profile:     conform.ProfileCore,
		EvidenceDir: evidenceDir,
		ProjectRoot: projectRoot,
		Clock:       time.Now,
		ExtraConfig: map[string]any{},
	}
}

func TestG2G3Gates_AreReachable(t *testing.T) {
	ctx := setupGateCtx(t)

	g2 := &G2Replay{}
	require.NotEmpty(t, g2.Name())
	r2 := g2.Run(ctx)
	require.False(t, r2.Pass)
	require.Contains(t, r2.Reasons, conform.ReasonReplayTapeMiss)

	g2a := &G2ASchemaFirst{}
	require.NotEmpty(t, g2a.Name())
	r2a := g2a.Run(ctx)
	require.False(t, r2a.Pass)
	require.Contains(t, r2a.Reasons, conform.ReasonSchemaValidationFailed)

	g3 := &G3Policy{}
	require.NotEmpty(t, g3.Name())
	r3 := g3.Run(ctx)
	require.False(t, r3.Pass)
	require.Contains(t, r3.Reasons, conform.ReasonPolicyDecisionMissing)

	g3a := &G3ABudget{}
	require.NotEmpty(t, g3a.Name())
	r3a := g3a.Run(ctx)
	require.False(t, r3a.Pass)
	require.Contains(t, r3a.Reasons, conform.ReasonBudgetExhausted)
}
