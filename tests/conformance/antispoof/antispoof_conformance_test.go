package antispoof_conformance

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/channels"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/packs/antispoof"
)

// TestAntiSpoofConformance_AllScenariosBlocked runs the full anti-spoof pack
// against DefaultAntiSpoofValidator and verifies that every scenario is blocked.
func TestAntiSpoofConformance_AllScenariosBlocked(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)
	require.NotNil(t, result)

	t.Run("all_scenarios_are_blocked", func(t *testing.T) {
		assert.Equal(t, result.TotalScenarios, result.Blocked,
			"every scenario must be blocked; bypassed=%d", result.Bypassed)
	})

	t.Run("no_scenarios_bypass_validator", func(t *testing.T) {
		assert.Equal(t, 0, result.Bypassed)
	})

	t.Run("eight_scenarios_executed", func(t *testing.T) {
		assert.Equal(t, 8, result.TotalScenarios)
	})
}

// TestAntiSpoofConformance_ContentHashIsDeterministic verifies that the pack
// produces the same content hash on two independent runs.
func TestAntiSpoofConformance_ContentHashIsDeterministic(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result1, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)

	result2, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)

	t.Run("content_hash_stable_across_runs", func(t *testing.T) {
		assert.Equal(t, result1.ContentHash, result2.ContentHash,
			"content hash must be deterministic for identical inputs")
	})

	t.Run("content_hash_is_sha256_hex", func(t *testing.T) {
		assert.Len(t, result1.ContentHash, 64,
			"SHA-256 hex digest must be exactly 64 characters")
	})
}

// TestAntiSpoofConformance_PackResultStructure verifies that every required
// field in PackResult is populated after a successful run.
func TestAntiSpoofConformance_PackResultStructure(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)
	require.NotNil(t, result)

	t.Run("pack_id_is_non_empty", func(t *testing.T) {
		assert.NotEmpty(t, result.PackID)
	})

	t.Run("total_scenarios_matches_default_count", func(t *testing.T) {
		assert.Equal(t, len(antispoof.DefaultScenarios()), result.TotalScenarios)
	})

	t.Run("results_slice_length_matches_total_scenarios", func(t *testing.T) {
		assert.Len(t, result.Results, result.TotalScenarios)
	})

	t.Run("blocked_plus_bypassed_equals_total", func(t *testing.T) {
		assert.Equal(t, result.TotalScenarios, result.Blocked+result.Bypassed)
	})

	t.Run("content_hash_is_non_empty", func(t *testing.T) {
		assert.NotEmpty(t, result.ContentHash)
	})
}

// TestAntiSpoofConformance_ScenarioResultFields verifies that each individual
// ScenarioResult has the required fields populated.
func TestAntiSpoofConformance_ScenarioResultFields(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)

	for _, r := range result.Results {
		t.Run(r.ScenarioName, func(t *testing.T) {
			assert.NotEmpty(t, r.ScenarioName)
			assert.NotEmpty(t, r.DetectedAs)
			assert.GreaterOrEqual(t, r.ResponseMs, int64(0))
			// All spoofed envelopes must be blocked.
			assert.True(t, r.Blocked,
				"scenario %q must be blocked by DefaultAntiSpoofValidator", r.ScenarioName)
			assert.Equal(t, string(channels.SenderTrustSuspicious), r.DetectedAs,
				"blocked scenario %q must be detected as suspicious", r.ScenarioName)
		})
	}
}

// TestAntiSpoofConformance_AllDefaultScenariosPresent verifies that the result
// contains one entry for each scenario returned by DefaultScenarios.
func TestAntiSpoofConformance_AllDefaultScenariosPresent(t *testing.T) {
	pack := &antispoof.AntiSpoofPack{Scenarios: antispoof.DefaultScenarios()}
	validator := channels.NewAntiSpoofValidator()

	result, err := pack.Run(context.Background(), validator)
	require.NoError(t, err)

	expectedNames := make(map[string]struct{})
	for _, s := range antispoof.DefaultScenarios() {
		expectedNames[s.Name] = struct{}{}
	}

	t.Run("all_default_scenarios_appear_in_results", func(t *testing.T) {
		for _, r := range result.Results {
			_, ok := expectedNames[r.ScenarioName]
			assert.True(t, ok, "unexpected scenario in results: %q", r.ScenarioName)
		}
		assert.Len(t, result.Results, len(expectedNames))
	})
}
