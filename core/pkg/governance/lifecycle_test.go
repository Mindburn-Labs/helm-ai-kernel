package governance

import (
	"context"
	"testing"

	"github.com/Mindburn-Labs/helm-oss/core/pkg/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRegistry
type MockRegistry struct {
	mock.Mock
}

func (m *MockRegistry) ApplyPhenotype(modules []ModuleBundle) error {
	args := m.Called(modules)
	return args.Error(0)
}

// MockPolicyEvaluator
type MockPolicyEvaluator struct {
	mock.Mock
}

func (m *MockPolicyEvaluator) VerifyModulePolicy(ctx context.Context, newModule ModuleBundle) error {
	args := m.Called(ctx, newModule)
	return args.Error(0)
}

func TestValidateModuleDependencies_CycleDetection(t *testing.T) {
	mockPE := &MockPolicyEvaluator{}
	lm := NewLifecycleManager(&MockRegistry{}, mockPE)

	currentModules := map[string]ModuleBundle{
		"A": {ID: "A", Dependencies: []string{"B"}},
		"B": {ID: "B", Dependencies: []string{"C"}},
		"C": {ID: "C", Dependencies: []string{}},
	}

	// Expect policy check
	mockPE.On("VerifyModulePolicy", mock.Anything, mock.Anything).Return(nil)

	// 1. Valid case
	newModule := ModuleBundle{ID: "D", Dependencies: []string{"A"}}
	err := lm.ValidateModuleDependencies(context.Background(), newModule, currentModules)
	assert.NoError(t, err)

	// 2. Cycle case: D depends on A, A->B->C. If C depends on D, cycle.
	// But we are adding D.
	// Let's make C depend on D in the "current" modules? No, C is already there.
	// Let's add E that depends on A. A depends on B. B depends on E (cycle).
	// Current: A->B
	// New: B->A (cycle if we add B again? No keys are unique).

	// Cycle: A->B, B->A.
	// Existing: A->B.
	// New: B (update) -> A.
	currentModules2 := map[string]ModuleBundle{
		"A": {ID: "A", Dependencies: []string{"B"}},
	}
	newModuleCycle := ModuleBundle{ID: "B", Dependencies: []string{"A"}}

	err = lm.ValidateModuleDependencies(context.Background(), newModuleCycle, currentModules2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cycle detected")
}

func TestExecuteActivation(t *testing.T) {
	mockReg := &MockRegistry{}
	mockPE := &MockPolicyEvaluator{}
	lm := NewLifecycleManager(mockReg, mockPE)

	newModule := ModuleBundle{ID: "NewMod", Dependencies: []string{}}
	action := ActionActivateModule{ModuleBundle: newModule}

	mockPE.On("VerifyModulePolicy", mock.Anything, newModule).Return(nil)
	mockReg.On("ApplyPhenotype", []ModuleBundle{newModule}).Return(nil)

	// 1. Pass
	decision := &contracts.DecisionRecord{Verdict: string(contracts.VerdictAllow)}
	err := lm.ExecuteActivation(context.Background(), action, decision, map[string]ModuleBundle{})
	assert.NoError(t, err)

	// 2. Fail Decision
	decisionFail := &contracts.DecisionRecord{Verdict: string(contracts.VerdictDeny), Reason: "No"}
	err = lm.ExecuteActivation(context.Background(), action, decisionFail, map[string]ModuleBundle{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "activation denied")

	mockReg.AssertExpectations(t)
	mockPE.AssertExpectations(t)
}
