package governance

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/capabilities"
	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
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

	env, err := sc.Advise(context.Background(), "scale", nil)
	require.NoError(t, err)
	// Since GetLabel might not exist or we need to unmarshal payload
	assert.Contains(t, string(env.Payload), "GREEN")
}

func TestStateEstimator(t *testing.T) {
	se := NewStateEstimator("test-producer", &MockSigner{})
	assert.Equal(t, "state.estimator", se.Name())

	env, err := se.Advise(context.Background(), "scale", nil)
	require.NoError(t, err)
	assert.Contains(t, string(env.Payload), "confidence")
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

func TestPolicyInductor(t *testing.T) {
	pi := NewPolicyInductor("test-producer", &MockSigner{})
	assert.Equal(t, "policy.inductor", pi.Name())

	env, err := pi.Advise(context.Background(), "deploy", nil)
	require.NoError(t, err)
	assert.Contains(t, string(env.Payload), "pol-generic-allow")
}
