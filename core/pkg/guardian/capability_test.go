package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capability"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
)

func loadTestCapabilityRegistry(t *testing.T) *capability.Registry {
	t.Helper()
	reg, err := capability.LoadDir("../capability/testdata/valid")
	require.NoError(t, err)
	return reg
}

func TestEvaluateDecision_UnknownCapability_Escalates(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))

	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Resource:  "gui-action",
		Context: map[string]interface{}{
			ContextKeyCapabilityID: "helm.cap.does.not.exist",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictEscalate), decision.Verdict)
	assert.Equal(t, string(contracts.ReasonCapabilityUnknown), decision.ReasonCode)
	assert.Contains(t, decision.Reason, "helm.cap.does.not.exist")
	assert.NotEmpty(t, decision.Signature, "quarantine decision must be signed")
}

func TestEvaluateDecision_ManifestDrift_Denies(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))

	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Resource:  "gui-action",
		Context: map[string]interface{}{
			ContextKeyCapabilityID:           "helm.cap.gui.gelab.tap",
			ContextKeyCapabilityManifestHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictDeny), decision.Verdict)
	assert.Equal(t, string(contracts.ReasonCapabilityManifestDrift), decision.ReasonCode)
	assert.Contains(t, decision.Reason, "manifest drift")
	assert.NotEmpty(t, decision.Signature)
}

func TestResolveCapabilityGate_EnrichesContext(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))
	entry := reg.Resolve("helm.cap.gui.gelab.tap")
	require.NotNil(t, entry)

	span := noop.NewTracerProvider().Tracer("test")
	ctx, sp := span.Start(context.Background(), "gate")
	_ = ctx

	req := &DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Context: map[string]interface{}{
			ContextKeyCapabilityID:           "helm.cap.gui.gelab.tap",
			ContextKeyCapabilityManifestHash: entry.Hash,
		},
	}
	decision, handled := g.resolveCapabilityGate(sp, req)
	assert.False(t, handled)
	assert.Nil(t, decision)

	assert.Equal(t, entry.Hash, req.Context["capability_manifest_hash"])
	assert.Equal(t, "write_external", req.Context["capability_effect_class"])
	assert.Equal(t, "compensating_action", req.Context["capability_reversibility"])
	assert.Equal(t, "device_boundary", req.Context["capability_data_boundary"])
	assert.Equal(t, 40, req.Context["capability_risk_score"])
	assert.Equal(t, "none", req.Context["capability_required_permit_level"])
	assert.Equal(t, "fast_edge", req.Context["capability_min_model_tier"])
}

func TestResolveCapabilityGate_NoRegistry_IsNoop(t *testing.T) {
	g := NewGuardian(&MockSigner{}, nil, nil)
	span := noop.NewTracerProvider().Tracer("test")
	_, sp := span.Start(context.Background(), "gate")

	req := &DecisionRequest{Context: map[string]interface{}{
		ContextKeyCapabilityID: "helm.cap.anything.at.all",
	}}
	decision, handled := g.resolveCapabilityGate(sp, req)
	assert.False(t, handled)
	assert.Nil(t, decision)
	// Context must be untouched apart from the pre-existing key.
	_, hasHash := req.Context["capability_manifest_hash"]
	assert.False(t, hasHash)
}

func TestResolveCapabilityGate_NoCapabilityID_IsNoop(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))
	span := noop.NewTracerProvider().Tracer("test")
	_, sp := span.Start(context.Background(), "gate")

	req := &DecisionRequest{Principal: "agent-1", Action: "dispatch"}
	decision, handled := g.resolveCapabilityGate(sp, req)
	assert.False(t, handled)
	assert.Nil(t, decision)
}

func TestCapabilityReasonCodes_AreCanonical(t *testing.T) {
	for _, code := range []string{
		"CAPABILITY_UNKNOWN",
		"CAPABILITY_MANIFEST_DRIFT",
		"CAPABILITY_TOKEN_INVALID",
	} {
		assert.True(t, contracts.IsCanonicalReasonCode(code), "%s must be registered canonical", code)
	}
}
