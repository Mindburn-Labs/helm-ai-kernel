package guardian

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capability"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
)

func loadTestRollbackPlans(t *testing.T, reg *capability.Registry) *capability.RollbackPlanRegistry {
	t.Helper()
	store, err := capability.LoadRollbackDir("../capability/testdata/plans", reg)
	require.NoError(t, err)
	return store
}

// loadPartialRollbackPlans returns a plan store that contains only the
// navigate-back plan, so upload-photo's plan_ref is unresolvable.
func loadPartialRollbackPlans(t *testing.T, reg *capability.Registry) *capability.RollbackPlanRegistry {
	t.Helper()
	dir := t.TempDir()
	src, err := os.ReadFile("../capability/testdata/plans/navigate_back.json")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "navigate_back.json"), src, 0o600))
	store, err := capability.LoadRollbackDir(dir, reg)
	require.NoError(t, err)
	return store
}

func gateRequest(capabilityID string, extra map[string]interface{}) *DecisionRequest {
	ctx := map[string]interface{}{ContextKeyCapabilityID: capabilityID}
	for k, v := range extra {
		ctx[k] = v
	}
	return &DecisionRequest{Principal: "agent-1", Action: "dispatch", Context: ctx}
}

func runGate(g *Guardian, req *DecisionRequest) (*contracts.DecisionRecord, bool) {
	span := noop.NewTracerProvider().Tracer("test")
	_, sp := span.Start(context.Background(), "gate")
	return g.resolveCapabilityGate(sp, req)
}

func TestReversibility_ReversibleLocal_BindsPlan(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	plans := loadTestRollbackPlans(t, reg)
	g := NewGuardian(&MockSigner{}, nil, nil,
		WithCapabilityRegistry(reg), WithRollbackPlanStore(plans))

	req := gateRequest("helm.cap.gui.gelab.tap", nil)
	decision, handled := runGate(g, req)
	assert.False(t, handled)
	assert.Nil(t, decision)
	assert.Equal(t, "plans/gui-navigate-back.v1", req.Context["capability_rollback_plan_id"])
	assert.NotEmpty(t, req.Context["capability_rollback_plan_hash"])
}

func TestReversibility_MissingPlan_Denies(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	partial := loadPartialRollbackPlans(t, reg)
	g := NewGuardian(&MockSigner{}, nil, nil,
		WithCapabilityRegistry(reg), WithRollbackPlanStore(partial))

	// upload-photo's plan_ref is NOT in the partial store; approval is
	// present so only the missing plan can stop this dispatch.
	req := gateRequest("helm.cap.gui.gelab.upload-photo",
		map[string]interface{}{ContextKeyApprovalReceiptRef: "rcpt_approval_1"})
	decision, handled := runGate(g, req)
	require.True(t, handled)
	require.NotNil(t, decision)
	assert.Equal(t, string(contracts.VerdictDeny), decision.Verdict)
	assert.Equal(t, string(contracts.ReasonCapabilityRollbackPlanInvalid), decision.ReasonCode)
}

func TestReversibility_ReversibleExternal_EscalatesWithoutApproval(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	plans := loadTestRollbackPlans(t, reg)
	g := NewGuardian(&MockSigner{}, nil, nil,
		WithCapabilityRegistry(reg), WithRollbackPlanStore(plans))

	req := gateRequest("helm.cap.gui.gelab.upload-photo", nil)
	decision, handled := runGate(g, req)
	require.True(t, handled)
	require.NotNil(t, decision)
	assert.Equal(t, string(contracts.VerdictEscalate), decision.Verdict)
	assert.Equal(t, string(contracts.ReasonApprovalRequired), decision.ReasonCode)
	// The plan was still bound before the escalation, for the permit flow.
	assert.Equal(t, "plans/gui-delete-upload.v1", decision.InputContext["capability_rollback_plan_id"])
}

func TestReversibility_ReversibleExternal_PassesWithApproval(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	plans := loadTestRollbackPlans(t, reg)
	g := NewGuardian(&MockSigner{}, nil, nil,
		WithCapabilityRegistry(reg), WithRollbackPlanStore(plans))

	req := gateRequest("helm.cap.gui.gelab.upload-photo",
		map[string]interface{}{ContextKeyApprovalReceiptRef: "rcpt_approval_1"})
	decision, handled := runGate(g, req)
	assert.False(t, handled)
	assert.Nil(t, decision)
}

func TestReversibility_IrreversibleClass_DeniesWithoutApproval(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))

	req := gateRequest("helm.cap.msg.send-external", nil)
	decision, handled := runGate(g, req)
	require.True(t, handled)
	require.NotNil(t, decision)
	assert.Equal(t, string(contracts.VerdictDeny), decision.Verdict)
	assert.Equal(t, string(contracts.ReasonCapabilityIrreversible), decision.ReasonCode)
}

func TestReversibility_IrreversibleClass_PassesWithApproval(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))

	req := gateRequest("helm.cap.msg.send-external",
		map[string]interface{}{ContextKeyApprovalReceiptRef: "rcpt_approval_1"})
	decision, handled := runGate(g, req)
	assert.False(t, handled)
	assert.Nil(t, decision)
}

func TestReversibility_IrreversibleExternalReach_Escalates(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))

	req := gateRequest("helm.cap.net.fetch", nil)
	decision, handled := runGate(g, req)
	require.True(t, handled)
	require.NotNil(t, decision)
	assert.Equal(t, string(contracts.VerdictEscalate), decision.Verdict)
	assert.Equal(t, string(contracts.ReasonApprovalRequired), decision.ReasonCode)
}

func TestReversibility_IrreversibleExternalReach_PassesWithApproval(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))

	req := gateRequest("helm.cap.net.fetch",
		map[string]interface{}{ContextKeyApprovalReceiptRef: "rcpt_approval_1"})
	decision, handled := runGate(g, req)
	assert.False(t, handled)
	assert.Nil(t, decision)
}

func TestReversibility_ReadOnly_Unaffected(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))

	req := gateRequest("helm.cap.fs.read", nil)
	decision, handled := runGate(g, req)
	assert.False(t, handled)
	assert.Nil(t, decision)
}

func TestReversibility_NoPlanStore_RecordsRefOnly(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))

	req := gateRequest("helm.cap.gui.gelab.tap", nil)
	decision, handled := runGate(g, req)
	assert.False(t, handled)
	assert.Nil(t, decision)
	assert.Equal(t, "plans/gui-navigate-back.v1", req.Context["capability_rollback_plan_ref"])
	_, hasID := req.Context["capability_rollback_plan_id"]
	assert.False(t, hasID, "without a plan store no plan is bound")
}
