package guardian

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/capability"
	"github.com/Mindburn-Labs/helm-ai-kernel/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func loadTestRollbackPlans(t *testing.T, reg *capability.Registry) *capability.RollbackPlanRegistry {
	t.Helper()
	store, err := capability.LoadRollbackDir("../capability/testdata/plans", reg)
	require.NoError(t, err)
	return store
}

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

type staticRollbackPlanStore struct {
	entry *capability.RollbackPlanEntry
}

func (s staticRollbackPlanStore) ResolvePlan(string) *capability.RollbackPlanEntry { return s.entry }
func (s staticRollbackPlanStore) Len() int                                         { return 1 }

func rollbackRequest(capabilityID string) *DecisionRequest {
	return &DecisionRequest{
		Principal: "agent-1",
		Action:    "dispatch",
		Context:   map[string]interface{}{ContextKeyCapabilityID: capabilityID},
	}
}

func TestReversibility_ReversibleLocalBindsPlan(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	plans := loadTestRollbackPlans(t, reg)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg), WithRollbackPlanStore(plans))

	req := rollbackRequest("helm.cap.gui.gelab.tap")
	decision, err := g.resolveCapabilityGate(testCapabilitySpan(t), req, nil, "sha256:policy")
	require.NoError(t, err)
	assert.Nil(t, decision)
	assert.Equal(t, "plans/gui-navigate-back.v1", req.Context["capability_rollback_plan_id"])
	assert.NotEmpty(t, req.Context["capability_rollback_plan_hash"])
}

func TestReversibility_MissingStoreOrPlanDenies(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	for name, store := range map[string]capability.RollbackPlanStore{
		"store missing": nil,
		"plan missing":  loadPartialRollbackPlans(t, reg),
	} {
		t.Run(name, func(t *testing.T) {
			g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg), WithRollbackPlanStore(store))
			req := rollbackRequest("helm.cap.gui.gelab.upload-photo")
			req.Context[ContextKeyCapabilityToken] = map[string]interface{}{"secret": "must-not-be-signed"}
			decision, err := g.resolveCapabilityGate(testCapabilitySpan(t), req, nil, "sha256:policy")
			require.NoError(t, err)
			require.NotNil(t, decision)
			assert.Equal(t, string(contracts.ReasonCapabilityRollbackPlanInvalid), decision.ReasonCode)
			assert.NotContains(t, decision.InputContext, ContextKeyCapabilityToken)
		})
	}
}

func TestReversibility_WrongOrExpiredPlanDenies(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	entry := *loadTestRollbackPlans(t, reg).ResolvePlan("plans/gui-navigate-back.v1")
	entry.Plan.AppliesTo.CapabilityID = "helm.cap.fs.read"
	wrongStore := staticRollbackPlanStore{entry: &entry}
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg), WithRollbackPlanStore(wrongStore))
	decision, err := g.resolveCapabilityGate(testCapabilitySpan(t), rollbackRequest("helm.cap.gui.gelab.tap"), nil, "sha256:policy")
	require.NoError(t, err)
	assert.Equal(t, string(contracts.ReasonCapabilityRollbackPlanInvalid), decision.ReasonCode)

	entry = *loadTestRollbackPlans(t, reg).ResolvePlan("plans/gui-navigate-back.v1")
	past := time.Date(2026, 2, 9, 12, 0, 0, 0, time.UTC)
	entry.Plan.GuaranteeExpiry = &past
	clock := newFixedClock()
	g = NewGuardian(&MockSigner{}, nil, nil,
		WithClock(clock),
		WithCapabilityRegistry(reg),
		WithRollbackPlanStore(staticRollbackPlanStore{entry: &entry}),
	)
	decision, err = g.resolveCapabilityGate(testCapabilitySpan(t), rollbackRequest("helm.cap.gui.gelab.tap"), nil, "sha256:policy")
	require.NoError(t, err)
	assert.Equal(t, string(contracts.ReasonCapabilityRollbackPlanInvalid), decision.ReasonCode)
}

func TestReversibility_ExternalEscalatesAfterPlanBinding(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg), WithRollbackPlanStore(loadTestRollbackPlans(t, reg)))
	decision, err := g.resolveCapabilityGate(testCapabilitySpan(t), rollbackRequest("helm.cap.gui.gelab.upload-photo"), nil, "sha256:policy")
	require.NoError(t, err)
	require.NotNil(t, decision)
	assert.Equal(t, string(contracts.VerdictEscalate), decision.Verdict)
	assert.Equal(t, string(contracts.ReasonApprovalRequired), decision.ReasonCode)
	assert.Equal(t, "plans/gui-delete-upload.v1", decision.InputContext["capability_rollback_plan_id"])
}

func TestReversibility_IrreversibleAndReadOnly(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))
	decision, err := g.resolveCapabilityGate(testCapabilitySpan(t), rollbackRequest("helm.cap.msg.send-external"), nil, "sha256:policy")
	require.NoError(t, err)
	assert.Equal(t, string(contracts.ReasonCapabilityIrreversible), decision.ReasonCode)

	decision, err = g.resolveCapabilityGate(testCapabilitySpan(t), rollbackRequest("helm.cap.fs.read"), nil, "sha256:policy")
	require.NoError(t, err)
	assert.Nil(t, decision)
}

func TestReversibility_NonReversibleCapabilityEscalates(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithCapabilityRegistry(reg))
	decision, err := g.resolveCapabilityGate(testCapabilitySpan(t), rollbackRequest("helm.cap.net.fetch"), nil, "sha256:policy")
	require.NoError(t, err)
	assert.Equal(t, string(contracts.ReasonApprovalRequired), decision.ReasonCode)
}

func TestCapabilityRollbackRosterAndReasonCodes(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(&MockSigner{}, nil, nil, WithRollbackPlanStore(loadTestRollbackPlans(t, reg)))
	assert.Contains(t, g.GateRoster().Active, GateCapabilityRollback)
	for _, code := range []string{
		string(contracts.ReasonCapabilityRollbackPlanInvalid),
		string(contracts.ReasonCapabilityIrreversible),
	} {
		assert.True(t, contracts.IsCanonicalReasonCode(code), "%s must be registered canonical", code)
	}
}

func TestReversibility_EvaluationStillRunsThroughGuardian(t *testing.T) {
	reg := loadTestCapabilityRegistry(t)
	g := NewGuardian(
		&MockSigner{},
		allowGraphFor("dispatch"),
		nil,
		WithCapabilityRegistry(reg),
		WithRollbackPlanStore(loadTestRollbackPlans(t, reg)),
	)
	decision, err := g.EvaluateDecision(context.Background(), *rollbackRequest("helm.cap.gui.gelab.tap"))
	require.NoError(t, err)
	assert.Equal(t, string(contracts.VerdictAllow), decision.Verdict)
}
