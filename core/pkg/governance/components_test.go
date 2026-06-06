package governance

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capabilities"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockSigner implementation for testing
type MockSigner struct{}

func (m *MockSigner) Sign(data []byte) (string, error) { return "sig", nil }
func (m *MockSigner) PublicKey() string                { return "key" }
func (m *MockSigner) PublicKeyBytes() []byte           { return []byte("key") }
func (m *MockSigner) SignDecision(d *contracts.DecisionRecord) error {
	d.Signature = "sig"
	return nil
}
func (m *MockSigner) SignIntent(i *contracts.AuthorizedExecutionIntent) error {
	i.Signature = "sig"
	return nil
}
func (m *MockSigner) SignReceipt(r *contracts.Receipt) error {
	r.Signature = "sig"
	return nil
}
func (m *MockSigner) VerifyDecision(d *contracts.DecisionRecord) (bool, error) {
	return true, nil
}
func (m *MockSigner) VerifyIntent(i *contracts.AuthorizedExecutionIntent) (bool, error) {
	return true, nil
}
func (m *MockSigner) VerifyReceipt(r *contracts.Receipt) (bool, error) {
	return true, nil
}

func TestEvolutionGovernance(t *testing.T) {
	gov := NewEvolutionGovernance()

	// C0/C1
	ok, _ := gov.EvaluateChange(context.Background(), ChangeClassC0, true)
	assert.True(t, ok)
	ok, _ = gov.EvaluateChange(context.Background(), ChangeClassC0, false)
	assert.False(t, ok)

	// C2
	ok, _ = gov.EvaluateChange(context.Background(), ChangeClassC2, true)
	assert.True(t, ok)
	ok, _ = gov.EvaluateChange(context.Background(), ChangeClassC2, false)
	assert.False(t, ok)

	// C3
	ok, _ = gov.EvaluateChange(context.Background(), ChangeClassC3, true)
	assert.False(t, ok) // Always manual

	// Unknown
	ok, _ = gov.EvaluateChange(context.Background(), "unknown", true)
	assert.False(t, ok)
}

func TestSignalController(t *testing.T) {
	sc := NewSignalController("test-producer", &MockSigner{})
	assert.Equal(t, "signal.controller", sc.Name())

	env, err := sc.Advise(context.Background(), "scale", map[string]any{
		"health":     99.9,
		"error_rate": 0.001,
		"latency_ms": 120,
		"saturation": 0.4,
		"safe":       true,
		"approved":   true,
	})
	require.NoError(t, err)
	payload := decodeSignalPayload(t, env.Payload)
	assert.Equal(t, "GREEN", payload["signal"])
	assert.Equal(t, "metrics_nominal", payload["check"])
	assert.Equal(t, "scale", payload["intent"])
}

func TestSignalController_DerivesWarningsFromContext(t *testing.T) {
	sc := NewSignalController("test-producer", &MockSigner{})

	env, err := sc.Advise(context.Background(), "scale", nil)
	require.NoError(t, err)
	payload := decodeSignalPayload(t, env.Payload)
	assert.Equal(t, "WARN", payload["signal"])
	assert.NotContains(t, string(env.Payload), "all_systems_nominal")

	env, err = sc.Advise(context.Background(), "production destroy", map[string]any{
		"health":            72,
		"error_rate":        0.15,
		"latency_ms":        7000,
		"saturation":        0.99,
		"active_incident":   true,
		"unsafe":            true,
		"requires_approval": true,
		"approved":          false,
		"signal":            "GREEN",
	})
	require.NoError(t, err)
	payload = decodeSignalPayload(t, env.Payload)
	assert.Equal(t, "CRITICAL", payload["signal"])
	assert.Equal(t, "metrics_degraded", payload["check"])
	assert.Contains(t, string(env.Payload), "health_below_critical_threshold")
	assert.NotContains(t, string(env.Payload), `"signal":"GREEN"`)
}

func TestSignalController_FailClosedEdges(t *testing.T) {
	sc := NewSignalController("test-producer", &MockSigner{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := sc.Advise(ctx, "scale", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")

	unsigned := NewSignalController("test-producer", nil)
	_, err = unsigned.Advise(context.Background(), "scale", nil)
	assert.Error(t, err)
}

func decodeSignalPayload(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var payload map[string]any
	require.NoError(t, json.Unmarshal(raw, &payload))
	return payload
}

func TestStateEstimator(t *testing.T) {
	se := NewStateEstimator("test-producer", &MockSigner{})
	assert.Equal(t, "state.estimator", se.Name())

	env, err := se.Advise(context.Background(), "scale", nil)
	require.NoError(t, err)
	assert.Contains(t, string(env.Payload), "confidence")
}

func TestStateEstimator_FailClosedEdges(t *testing.T) {
	se := NewStateEstimator("test-producer", &MockSigner{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := se.Advise(ctx, "scale", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "context canceled")

	unsigned := NewStateEstimator("test-producer", nil)
	_, err = unsigned.Advise(context.Background(), "scale", nil)
	assert.Error(t, err)
}

func TestComputePowerDelta(t *testing.T) {
	existing := []capabilities.Capability{
		{ID: "cap-1", EffectClass: "E1"},
	}

	newModule := ModuleBundle{
		Capabilities: []capabilities.Capability{
			{ID: "cap-1", EffectClass: "E1"}, // Existing
			{ID: "cap-2", EffectClass: "E2"}, // New (+5)
			{ID: "cap-3", EffectClass: "E4"}, // New (+20)
		},
	}

	delta := ComputePowerDelta(existing, newModule)

	assert.Len(t, delta.NewCapabilities, 2)
	assert.Equal(t, 25, delta.RiskScoreDelta)
}

func TestComputePowerDelta_ScoresRemainingEffectClasses(t *testing.T) {
	newModule := ModuleBundle{
		Capabilities: []capabilities.Capability{
			{ID: "cap-e3", EffectClass: "E3", Effects: []capabilities.EffectType{"write"}},
			{ID: "cap-e1", EffectClass: "E1", Effects: []capabilities.EffectType{"read"}},
			{ID: "cap-e0", EffectClass: "E0", Effects: []capabilities.EffectType{"observe"}},
		},
	}

	delta := ComputePowerDelta(nil, newModule)

	assert.Len(t, delta.NewCapabilities, 3)
	assert.Equal(t, 13, delta.RiskScoreDelta)
	assert.Equal(t, []capabilities.EffectType{"write", "read", "observe"}, delta.NewEffects)
}

func TestPolicyInductor(t *testing.T) {
	pi := NewPolicyInductor("test-producer", &MockSigner{})
	assert.Equal(t, "policy.inductor", pi.Name())

	env, err := pi.Advise(context.Background(), "deploy", nil)
	require.NoError(t, err)
	assert.Contains(t, string(env.Payload), "pol-generic-allow")
}

func TestPolicyInductor_FailClosedSigning(t *testing.T) {
	pi := NewPolicyInductor("test-producer", nil)
	_, err := pi.Advise(context.Background(), "deploy", nil)
	assert.Error(t, err)
}
