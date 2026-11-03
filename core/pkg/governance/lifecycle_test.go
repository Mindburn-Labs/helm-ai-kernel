package governance

import (
	"context"

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
