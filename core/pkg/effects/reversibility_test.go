package effects

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// ReversibilityLevel helpers
// ---------------------------------------------------------------------------

func TestReversibilityLevel_IsValid(t *testing.T) {
	tests := []struct {
		level ReversibilityLevel
		valid bool
	}{
		{ReversibilityFull, true},
		{ReversibilityPartial, true},
		{ReversibilityNone, true},
		{"UNKNOWN", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(string(tc.level), func(t *testing.T) {
			assert.Equal(t, tc.valid, tc.level.IsValid())
		})
	}
}

func TestReversibilityLevel_RequiresApproval(t *testing.T) {
	assert.False(t, ReversibilityFull.RequiresApproval(), "FULLY_REVERSIBLE should not require approval")
	assert.True(t, ReversibilityPartial.RequiresApproval(), "PARTIALLY_REVERSIBLE should require approval")
	assert.True(t, ReversibilityNone.RequiresApproval(), "IRREVERSIBLE should require approval")
}

func TestReversibilityLevel_RiskWeight(t *testing.T) {
	assert.Equal(t, 0, ReversibilityFull.RiskWeight())
	assert.Equal(t, 1, ReversibilityPartial.RiskWeight())
	assert.Equal(t, 2, ReversibilityNone.RiskWeight())

	// Unknown level defaults to maximum risk.
	unknown := ReversibilityLevel("BOGUS")
	assert.Equal(t, 2, unknown.RiskWeight())
}

// ---------------------------------------------------------------------------
// Default classifications for all 6 effect types
// ---------------------------------------------------------------------------

func TestDefaultClassifications(t *testing.T) {
	c := NewReversibilityClassifier()

	tests := []struct {
		effectType EffectType
		expected   ReversibilityLevel
	}{
		{EffectTypeRead, ReversibilityFull},
		{EffectTypeWrite, ReversibilityPartial},
		{EffectTypeDelete, ReversibilityNone},
		{EffectTypeExecute, ReversibilityPartial},
		{EffectTypeNetwork, ReversibilityPartial},
		{EffectTypeFinance, ReversibilityNone},
	}

	for _, tc := range tests {
		t.Run(string(tc.effectType), func(t *testing.T) {
			got := c.DefaultForType(tc.effectType)
			assert.Equal(t, tc.expected, got)

			// Classify with empty connector/tool should also return the default.
			got = c.Classify(tc.effectType, "", "")
			assert.Equal(t, tc.expected, got)
		})
	}
}

// ---------------------------------------------------------------------------
// Unknown effect type defaults to IRREVERSIBLE (fail-closed)
// ---------------------------------------------------------------------------

func TestUnknownEffectTypeDefaultsToIrreversible(t *testing.T) {
	c := NewReversibilityClassifier()

	unknown := EffectType("TELEPORT")
	assert.Equal(t, ReversibilityNone, c.DefaultForType(unknown))
	assert.Equal(t, ReversibilityNone, c.Classify(unknown, "conn-1", "do-teleport"))
}

// ---------------------------------------------------------------------------
// Override behavior
// ---------------------------------------------------------------------------

func TestSetOverride(t *testing.T) {
	c := NewReversibilityClassifier()

	// Without override, WRITE is PARTIALLY_REVERSIBLE.
	assert.Equal(t, ReversibilityPartial, c.Classify(EffectTypeWrite, "s3", "put-object"))

	// Set override: s3 put-object is fully reversible (versioned bucket).
	err := c.SetOverride("s3", "put-object", ReversibilityFull)
	require.NoError(t, err)

	// Now it should return the override.
	assert.Equal(t, ReversibilityFull, c.Classify(EffectTypeWrite, "s3", "put-object"))

	// Other tools on the same connector are unaffected.
	assert.Equal(t, ReversibilityPartial, c.Classify(EffectTypeWrite, "s3", "other-tool"))
}

func TestSetOverride_InvalidLevel(t *testing.T) {
	c := NewReversibilityClassifier()

	err := c.SetOverride("conn", "tool", ReversibilityLevel("BOGUS"))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidLevel)
}

func TestRemoveOverride(t *testing.T) {
	c := NewReversibilityClassifier()

	err := c.SetOverride("github", "delete-repo", ReversibilityFull)
	require.NoError(t, err)
	assert.Equal(t, ReversibilityFull, c.Classify(EffectTypeDelete, "github", "delete-repo"))

	c.RemoveOverride("github", "delete-repo")

	// After removal, should fall back to default for DELETE → IRREVERSIBLE.
	assert.Equal(t, ReversibilityNone, c.Classify(EffectTypeDelete, "github", "delete-repo"))
}

func TestRemoveOverride_NonExistent(t *testing.T) {
	c := NewReversibilityClassifier()

	// Removing a non-existent override should not panic.
	c.RemoveOverride("ghost", "phantom")
}

func TestOverridePrecedenceOverDefaults(t *testing.T) {
	c := NewReversibilityClassifier()

	// DELETE defaults to IRREVERSIBLE.
	assert.Equal(t, ReversibilityNone, c.Classify(EffectTypeDelete, "git", "soft-delete"))

	// Override: git soft-delete is fully reversible (soft delete with undo).
	err := c.SetOverride("git", "soft-delete", ReversibilityFull)
	require.NoError(t, err)

	// Override wins.
	assert.Equal(t, ReversibilityFull, c.Classify(EffectTypeDelete, "git", "soft-delete"))

	// Default for DELETE type is still IRREVERSIBLE.
	assert.Equal(t, ReversibilityNone, c.DefaultForType(EffectTypeDelete))
}

// ---------------------------------------------------------------------------
// Overrides snapshot isolation
// ---------------------------------------------------------------------------

func TestOverridesSnapshotIsolation(t *testing.T) {
	c := NewReversibilityClassifier()

	err := c.SetOverride("conn-a", "tool-1", ReversibilityFull)
	require.NoError(t, err)
	err = c.SetOverride("conn-b", "tool-2", ReversibilityNone)
	require.NoError(t, err)

	snapshot := c.Overrides()
	assert.Len(t, snapshot, 2)

	// Mutating the snapshot must not affect the classifier.
	snapshot[classifierKey{ConnectorID: "conn-c", ToolName: "tool-3"}] = ReversibilityPartial

	// Classifier still has only 2 overrides.
	assert.Len(t, c.Overrides(), 2)
}

// ---------------------------------------------------------------------------
// Thread safety
// ---------------------------------------------------------------------------

func TestConcurrentClassifyAndSetOverride(t *testing.T) {
	c := NewReversibilityClassifier()

	const goroutines = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half the goroutines set overrides.
	for i := range goroutines {
		go func(id int) {
			defer wg.Done()
			for j := range iterations {
				toolName := "tool"
				if j%2 == 0 {
					_ = c.SetOverride("conn", toolName, ReversibilityFull)
				} else {
					c.RemoveOverride("conn", toolName)
				}
				_ = id // prevent unused
			}
		}(i)
	}

	// Half the goroutines classify.
	for i := range goroutines {
		go func(id int) {
			defer wg.Done()
			for range iterations {
				level := c.Classify(EffectTypeWrite, "conn", "tool")
				// Must be one of the two valid outcomes.
				assert.True(t,
					level == ReversibilityFull || level == ReversibilityPartial,
					"unexpected level: %s", level,
				)
				_ = id
			}
		}(i)
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// ReversibilityPolicy — defaults
// ---------------------------------------------------------------------------

func TestDefaultReversibilityPolicy(t *testing.T) {
	p := DefaultReversibilityPolicy()

	assert.Equal(t, ReversibilityFull, p.MaxAutoApproveLevel)
	assert.Contains(t, p.RequireApprovalFor, ReversibilityPartial)
	assert.Contains(t, p.RequireApprovalFor, ReversibilityNone)
	assert.NotContains(t, p.RequireApprovalFor, ReversibilityFull)
	assert.Contains(t, p.RequireEvidenceFor, ReversibilityPartial)
	assert.Contains(t, p.RequireEvidenceFor, ReversibilityNone)
}

// ---------------------------------------------------------------------------
// Policy — approval requirements
// ---------------------------------------------------------------------------

func TestPolicy_ShouldRequireApproval(t *testing.T) {
	p := DefaultReversibilityPolicy()

	assert.False(t, p.ShouldRequireApproval(ReversibilityFull),
		"FULLY_REVERSIBLE should be auto-approved")
	assert.True(t, p.ShouldRequireApproval(ReversibilityPartial),
		"PARTIALLY_REVERSIBLE should require approval")
	assert.True(t, p.ShouldRequireApproval(ReversibilityNone),
		"IRREVERSIBLE should require approval")
}

func TestPolicy_ShouldRequireApproval_RiskWeightFallback(t *testing.T) {
	// Custom policy with empty RequireApprovalFor but a MaxAutoApproveLevel.
	p := &ReversibilityPolicy{
		RequireApprovalFor:  nil,
		MaxAutoApproveLevel: ReversibilityFull,
	}

	// PARTIALLY_REVERSIBLE has risk weight 1 > 0, so it should require approval
	// even though it is not in RequireApprovalFor.
	assert.True(t, p.ShouldRequireApproval(ReversibilityPartial))
	assert.True(t, p.ShouldRequireApproval(ReversibilityNone))
	assert.False(t, p.ShouldRequireApproval(ReversibilityFull))
}

// ---------------------------------------------------------------------------
// Policy — evidence requirements
// ---------------------------------------------------------------------------

func TestPolicy_ShouldRequireEvidence(t *testing.T) {
	p := DefaultReversibilityPolicy()

	assert.False(t, p.ShouldRequireEvidence(ReversibilityFull),
		"FULLY_REVERSIBLE should not require evidence by default")
	assert.True(t, p.ShouldRequireEvidence(ReversibilityPartial),
		"PARTIALLY_REVERSIBLE should require evidence")
	assert.True(t, p.ShouldRequireEvidence(ReversibilityNone),
		"IRREVERSIBLE should require evidence")
}

func TestPolicy_ShouldRequireEvidence_CustomPolicy(t *testing.T) {
	// Policy requiring evidence for everything.
	p := &ReversibilityPolicy{
		RequireEvidenceFor: []ReversibilityLevel{
			ReversibilityFull,
			ReversibilityPartial,
			ReversibilityNone,
		},
	}

	assert.True(t, p.ShouldRequireEvidence(ReversibilityFull))
	assert.True(t, p.ShouldRequireEvidence(ReversibilityPartial))
	assert.True(t, p.ShouldRequireEvidence(ReversibilityNone))
}

func TestPolicy_ShouldRequireEvidence_EmptyPolicy(t *testing.T) {
	p := &ReversibilityPolicy{}

	assert.False(t, p.ShouldRequireEvidence(ReversibilityFull))
	assert.False(t, p.ShouldRequireEvidence(ReversibilityPartial))
	assert.False(t, p.ShouldRequireEvidence(ReversibilityNone))
}

// ---------------------------------------------------------------------------
// Classifier — NewReversibilityClassifier starts clean
// ---------------------------------------------------------------------------

func TestNewReversibilityClassifier_EmptyOverrides(t *testing.T) {
	c := NewReversibilityClassifier()
	assert.Empty(t, c.Overrides())
}

// ---------------------------------------------------------------------------
// Multiple overrides on different keys are independent
// ---------------------------------------------------------------------------

func TestMultipleOverridesIndependent(t *testing.T) {
	c := NewReversibilityClassifier()

	require.NoError(t, c.SetOverride("conn-a", "tool-x", ReversibilityFull))
	require.NoError(t, c.SetOverride("conn-a", "tool-y", ReversibilityNone))
	require.NoError(t, c.SetOverride("conn-b", "tool-x", ReversibilityPartial))

	assert.Equal(t, ReversibilityFull, c.Classify(EffectTypeWrite, "conn-a", "tool-x"))
	assert.Equal(t, ReversibilityNone, c.Classify(EffectTypeWrite, "conn-a", "tool-y"))
	assert.Equal(t, ReversibilityPartial, c.Classify(EffectTypeWrite, "conn-b", "tool-x"))

	// Default still applies where no override exists.
	assert.Equal(t, ReversibilityPartial, c.Classify(EffectTypeWrite, "conn-b", "tool-y"))
}

// ---------------------------------------------------------------------------
// Override replacement
// ---------------------------------------------------------------------------

func TestOverrideReplacement(t *testing.T) {
	c := NewReversibilityClassifier()

	require.NoError(t, c.SetOverride("conn", "tool", ReversibilityFull))
	assert.Equal(t, ReversibilityFull, c.Classify(EffectTypeDelete, "conn", "tool"))

	// Replace with a different level.
	require.NoError(t, c.SetOverride("conn", "tool", ReversibilityNone))
	assert.Equal(t, ReversibilityNone, c.Classify(EffectTypeDelete, "conn", "tool"))
}
