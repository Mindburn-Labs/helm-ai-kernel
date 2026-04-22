package effects

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCostBreakdown_JSONSerialization(t *testing.T) {
	cb := CostBreakdown{
		InputTokens:    1500,
		OutputTokens:   300,
		ModelCostCents: 12,
		ToolCostCents:  5,
		TotalCents:     17,
	}

	data, err := json.Marshal(cb)
	require.NoError(t, err)

	var decoded CostBreakdown
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, cb.InputTokens, decoded.InputTokens)
	assert.Equal(t, cb.OutputTokens, decoded.OutputTokens)
	assert.Equal(t, cb.ModelCostCents, decoded.ModelCostCents)
	assert.Equal(t, cb.ToolCostCents, decoded.ToolCostCents)
	assert.Equal(t, cb.TotalCents, decoded.TotalCents)
}

func TestCostBreakdown_ZeroValuesOmitted(t *testing.T) {
	cb := CostBreakdown{
		TotalCents: 42,
	}

	data, err := json.Marshal(cb)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	// Zero-value fields with omitempty should be absent
	_, hasInputTokens := raw["input_tokens"]
	assert.False(t, hasInputTokens, "input_tokens should be omitted when zero")
	_, hasOutputTokens := raw["output_tokens"]
	assert.False(t, hasOutputTokens, "output_tokens should be omitted when zero")
	_, hasModelCost := raw["model_cost_cents"]
	assert.False(t, hasModelCost, "model_cost_cents should be omitted when zero")
	_, hasToolCost := raw["tool_cost_cents"]
	assert.False(t, hasToolCost, "tool_cost_cents should be omitted when zero")

	// TotalCents has no omitempty — it must always be present
	_, hasTotalCents := raw["total_cents"]
	assert.True(t, hasTotalCents, "total_cents should always be present")
}

func TestEffectOutcome_WithCostAttribution(t *testing.T) {
	outcome := EffectOutcome{
		RequestID: "req-001",
		PermitID:  "permit-001",
		Success:   true,
		Duration:  250 * time.Millisecond,
		CompletedAt: time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC),
		EstimatedCostCents: 25,
		CostBreakdown: &CostBreakdown{
			InputTokens:    2000,
			OutputTokens:   500,
			ModelCostCents: 20,
			ToolCostCents:  5,
			TotalCents:     25,
		},
	}

	data, err := json.Marshal(outcome)
	require.NoError(t, err)

	var decoded EffectOutcome
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, int64(25), decoded.EstimatedCostCents)
	require.NotNil(t, decoded.CostBreakdown)
	assert.Equal(t, int64(2000), decoded.CostBreakdown.InputTokens)
	assert.Equal(t, int64(500), decoded.CostBreakdown.OutputTokens)
	assert.Equal(t, int64(20), decoded.CostBreakdown.ModelCostCents)
	assert.Equal(t, int64(5), decoded.CostBreakdown.ToolCostCents)
	assert.Equal(t, int64(25), decoded.CostBreakdown.TotalCents)
}

func TestEffectOutcome_CostFieldsOmittedWhenZero(t *testing.T) {
	outcome := EffectOutcome{
		RequestID:   "req-002",
		PermitID:    "permit-002",
		Success:     true,
		Duration:    100 * time.Millisecond,
		CompletedAt: time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(outcome)
	require.NoError(t, err)

	var raw map[string]interface{}
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	_, hasCost := raw["estimated_cost_cents"]
	assert.False(t, hasCost, "estimated_cost_cents should be omitted when zero")
	_, hasBreakdown := raw["cost_breakdown"]
	assert.False(t, hasBreakdown, "cost_breakdown should be omitted when nil")
}

func TestEffectOutcome_NilCostBreakdown(t *testing.T) {
	outcome := EffectOutcome{
		RequestID:          "req-003",
		PermitID:           "permit-003",
		Success:            false,
		Error:              "connector timeout",
		Duration:           5 * time.Second,
		CompletedAt:        time.Date(2026, 4, 13, 12, 0, 5, 0, time.UTC),
		EstimatedCostCents: 3, // cost may still be estimated even on failure
	}

	data, err := json.Marshal(outcome)
	require.NoError(t, err)

	var decoded EffectOutcome
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, int64(3), decoded.EstimatedCostCents)
	assert.Nil(t, decoded.CostBreakdown)
}

func TestCostBreakdown_TotalCentsConsistency(t *testing.T) {
	// TotalCents should reflect ModelCostCents + ToolCostCents when both are set.
	// This is a convention enforced by callers; the struct is a plain data carrier.
	cb := CostBreakdown{
		InputTokens:    5000,
		OutputTokens:   1000,
		ModelCostCents: 45,
		ToolCostCents:  10,
		TotalCents:     55,
	}

	assert.Equal(t, cb.ModelCostCents+cb.ToolCostCents, cb.TotalCents,
		"TotalCents should equal ModelCostCents + ToolCostCents")
}

func TestCostBreakdown_LargeTokenCounts(t *testing.T) {
	// Verify int64 handles realistic large token counts (e.g., 128K context).
	cb := CostBreakdown{
		InputTokens:    128_000,
		OutputTokens:   4_096,
		ModelCostCents: 384, // $3.84
		TotalCents:     384,
	}

	data, err := json.Marshal(cb)
	require.NoError(t, err)

	var decoded CostBreakdown
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, int64(128_000), decoded.InputTokens)
	assert.Equal(t, int64(4_096), decoded.OutputTokens)
}

func TestEffectOutcome_BackwardCompatibility(t *testing.T) {
	// Old JSON without cost fields must still deserialize cleanly.
	oldJSON := `{
		"request_id": "req-legacy",
		"permit_id": "permit-legacy",
		"success": true,
		"duration": 500000000,
		"completed_at": "2026-04-13T12:00:00Z"
	}`

	var outcome EffectOutcome
	err := json.Unmarshal([]byte(oldJSON), &outcome)
	require.NoError(t, err)

	assert.Equal(t, "req-legacy", outcome.RequestID)
	assert.Equal(t, int64(0), outcome.EstimatedCostCents)
	assert.Nil(t, outcome.CostBreakdown)
}
