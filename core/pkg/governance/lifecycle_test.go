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

	newModule := ModuleBundle{ID: "D", Dependencies: []string{"A"}}
	err := lm.ValidateModuleDependencies(context.Background(), newModule, currentModules)
	assert.NoError(t, err)

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

	existingModule := ModuleBundle{ID: "ExistingMod", Dependencies: []string{}}
	newModule := ModuleBundle{ID: "NewMod", Dependencies: []string{}}
	action := ActionActivateModule{ModuleBundle: newModule}

	mockPE.On("VerifyModulePolicy", mock.Anything, newModule).Return(nil)
	mockReg.On("ApplyPhenotype", []ModuleBundle{existingModule, newModule}).Return(nil)

	decision := &contracts.DecisionRecord{Verdict: string(contracts.VerdictAllow)}
	err := lm.ExecuteActivation(context.Background(), action, decision, map[string]ModuleBundle{
		existingModule.ID: existingModule,
	})
	assert.NoError(t, err)

	decisionFail := &contracts.DecisionRecord{Verdict: string(contracts.VerdictDeny), Reason: "No"}
	err = lm.ExecuteActivation(context.Background(), action, decisionFail, map[string]ModuleBundle{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "activation denied")

	mockReg.AssertExpectations(t)
	mockPE.AssertExpectations(t)
}

func TestMergeModuleSet_ReplacesExistingModuleDeterministically(t *testing.T) {
	current := map[string]ModuleBundle{
		"b": {ID: "b", Policy: "old"},
		"a": {ID: "a", Policy: "keep"},
	}

	merged := mergeModuleSet(current, ModuleBundle{ID: "b", Policy: "new"})

	assert.Equal(t, []ModuleBundle{
		{ID: "a", Policy: "keep"},
		{ID: "b", Policy: "new"},
	}, merged)
}
