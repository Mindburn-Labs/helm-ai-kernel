package guardian

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capability"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	policyreconcile "github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/policy/reconcile"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/safedep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

func loadTestCapabilityRegistry(t *testing.T) *capability.Registry {
	t.Helper()
	reg, err := capability.LoadDir("../capability/testdata/valid")
	require.NoError(t, err)
	return reg
}

func testCapabilitySpan(t *testing.T) trace.Span {
	t.Helper()
	_, span := noop.NewTracerProvider().Tracer("capability-test").Start(context.Background(), "gate")
	t.Cleanup(func() { span.End() })
	return span
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
	assert.NotEmpty(t, decision.Signature)
}

func TestResolveCapabilityGate_EnrichesContext(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil,
		WithCapabilityRegistry(reg),
		WithRollbackPlanStore(loadTestRollbackPlans(t, reg)),
	)
	entry := reg.Resolve("helm.cap.gui.gelab.tap")
	require.NotNil(t, entry)

	req := &DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Context: map[string]interface{}{
			ContextKeyCapabilityID:           "helm.cap.gui.gelab.tap",
			ContextKeyCapabilityManifestHash: entry.Hash,
		},
	}
	decision, err := g.resolveCapabilityGate(testCapabilitySpan(t), req, nil, "sha256:policy")
	require.NoError(t, err)
	assert.Nil(t, decision)
	assert.Equal(t, entry.Hash, req.Context[ContextKeyCapabilityManifestHash])
	assert.Equal(t, "write_external", req.Context["capability_effect_class"])
	assert.Equal(t, "compensating_action", req.Context["capability_reversibility"])
	assert.Equal(t, "device_boundary", req.Context["capability_data_boundary"])
	assert.Equal(t, 40, req.Context["capability_risk_score"])
	assert.Equal(t, "none", req.Context["capability_required_permit_level"])
	assert.Equal(t, "fast_edge", req.Context["capability_min_model_tier"])
}

func TestResolveCapabilityGate_NoRegistryOrCapabilityID_IsNoop(t *testing.T) {
	req := &DecisionRequest{Context: map[string]interface{}{
		ContextKeyCapabilityID: "helm.cap.anything.at.all",
	}}
	g := NewGuardian(&MockSigner{}, nil, nil)
	decision, err := g.resolveCapabilityGate(testCapabilitySpan(t), req, nil, "")
	require.NoError(t, err)
	assert.Nil(t, decision)
	_, hasHash := req.Context[ContextKeyCapabilityManifestHash]
	assert.False(t, hasHash)

	reg := loadTestCapabilityRegistry(t)
	g = NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))
	req = &DecisionRequest{Principal: "agent-1", Action: "dispatch"}
	decision, err = g.resolveCapabilityGate(testCapabilitySpan(t), req, nil, "")
	require.NoError(t, err)
	assert.Nil(t, decision)
}

func TestCapabilityRegistryRosterIsObservable(t *testing.T) {
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(loadTestCapabilityRegistry(t)))
	for _, id := range g.GateRoster().Active {
		if id == GateCapabilityRegistry {
			return
		}
	}
	t.Fatalf("active roster = %v, want %q", g.GateRoster().Active, GateCapabilityRegistry)
}

func TestCapabilityGateRunsAfterSnapshotAndSafeDep(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	scope := policyreconcile.DefaultScope
	snapshotGuardian := NewGuardian(
		&MockSigner{},
		allowGraphFor("dispatch"),
		nil,
		WithCapabilityRegistry(reg),
		WithPolicySnapshots(policyreconcile.NewAtomicSnapshotStore(), scope),
	)
	decision, err := snapshotGuardian.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Resource:  "gui-action",
		Context:   map[string]interface{}{ContextKeyCapabilityID: "helm.cap.does.not.exist"},
	})
	require.NoError(t, err)
	assert.Equal(t, string(contracts.ReasonPolicyNotReady), decision.ReasonCode)

	clock := newFixedClock()
	safeDepGuardian := NewGuardian(
		&MockSigner{},
		allowGraphFor("WRITE"),
		nil,
		WithClock(clock),
		WithCapabilityRegistry(reg),
		WithSafeDepController(safedep.NewController(safedep.ControllerConfig{Clock: clock.Now})),
	)
	decision, err = safeDepGuardian.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "WRITE",
		Resource:  "connector",
		Context: map[string]interface{}{
			ContextKeyCapabilityID:            "helm.cap.does.not.exist",
			"safe_deprecation_hazard_code":    string(contracts.HazardDeadManExpired),
			"safe_deprecation_active_clock":   true,
			"safe_deprecation_high_risk_lane": true,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, string(contracts.ReasonSafeDepTerminalFreeze), decision.ReasonCode)
}

func TestCapabilityShortCircuitBindsActiveSnapshot(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	scope := policyreconcile.DefaultScope
	store := policyreconcile.NewAtomicSnapshotStore()
	require.NoError(t, store.Swap(scope, &policyreconcile.EffectivePolicySnapshot{
		TenantID:    scope.TenantID,
		WorkspaceID: scope.WorkspaceID,
		PolicyEpoch: 9,
		PolicyHash:  "sha256:capability-snapshot",
		Validation:  policyreconcile.ValidationStatus{Status: policyreconcile.StatusActive},
		Graph:       allowGraphFor("dispatch"),
	}))
	g := NewGuardian(
		&MockSigner{},
		allowGraphFor("dispatch"),
		nil,
		WithCapabilityRegistry(reg),
		WithPolicySnapshots(store, scope),
	)
	decision, err := g.EvaluateDecision(context.Background(), DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Resource:  "gui-action",
		Context:   map[string]interface{}{ContextKeyCapabilityID: "helm.cap.does.not.exist"},
	})
	require.NoError(t, err)
	assert.Equal(t, "sha256:capability-snapshot", decision.PolicyContentHash)
	assert.Equal(t, "9", decision.PolicyEpoch)
	assert.NotEmpty(t, decision.GateRosterHash)
}

func TestCapabilityRegistryReasonCodesAreCanonical(t *testing.T) {
	for _, code := range []string{"CAPABILITY_UNKNOWN", "CAPABILITY_MANIFEST_DRIFT"} {
		assert.True(t, contracts.IsCanonicalReasonCode(code), "%s must be registered canonical", code)
	}
}
