package pdp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTelemetryPDP_NormalMode(t *testing.T) {
	// Setup simple HelmPDP where "restricted_resource" is denied (false)
	rules := map[string]bool{
		"allowed_resource":    true,
		"restricted_resource": false,
	}
	inner := NewHelmPDP("test-v1", rules)

	// Wrap in TelemetryPDP
	telemetryPDP := NewTelemetryPDP(inner, false)

	// Evaluate allowed resource
	resp, err := telemetryPDP.Evaluate(context.Background(), &DecisionRequest{
		Resource:  "allowed_resource",
		Timestamp: time.Now(),
	})
	assert.NoError(t, err)
	assert.True(t, resp.Allow)
	assert.Empty(t, resp.ReasonCode)

	// Evaluate restricted resource
	resp, err = telemetryPDP.Evaluate(context.Background(), &DecisionRequest{
		Resource:  "restricted_resource",
		Timestamp: time.Now(),
	})
	assert.NoError(t, err)
	assert.False(t, resp.Allow)
	assert.Equal(t, "PDP_DENY", resp.ReasonCode)
}

func TestTelemetryPDP_ShadowMode(t *testing.T) {
	rules := map[string]bool{
		"restricted_resource": false,
	}
	inner := NewHelmPDP("test-v1", rules)

	// Wrap in TelemetryPDP with shadowMode = true
	telemetryPDP := NewTelemetryPDP(inner, true)
	assert.True(t, telemetryPDP.IsShadowMode())

	// Evaluate restricted resource in shadow mode
	resp, err := telemetryPDP.Evaluate(context.Background(), &DecisionRequest{
		Resource:  "restricted_resource",
		Timestamp: time.Now(),
	})
	assert.NoError(t, err)

	// Shadow mode must be observe-only; enforcement denies stay denied.
	assert.False(t, resp.Allow)
	assert.Equal(t, "PDP_DENY", resp.ReasonCode) // Reason code is preserved

	// Verify decision hash still binds the original deny decision.
	expectedHash, _ := ComputeDecisionHash(resp)
	assert.Equal(t, expectedHash, resp.DecisionHash)

	// Reset shadow mode and check
	telemetryPDP.SetShadowMode(false)
	assert.False(t, telemetryPDP.IsShadowMode())
}
