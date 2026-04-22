package governance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockFactOracle for testing
type MockFactOracle struct {
	Facts map[string]interface{}
}

func (m *MockFactOracle) GetFact(subject, predicate string) (interface{}, error) {
	key := subject + "|" + predicate
	if val, ok := m.Facts[key]; ok {
		return val, nil
	}
	return nil, errors.New("fact not found")
}

func TestPDP_FactCheck_DeployGate(t *testing.T) {
	// 1. Setup Oracle
	oracle := &MockFactOracle{
		Facts: map[string]interface{}{
			"repo:helm|build_status": "failed", // Build is failing!
		},
	}

	// 2. Setup PDP with Oracle
	pdp, err := NewCELPolicyDecisionPoint("sha256:test", oracle)
	require.NoError(t, err)

	// 3. Request: DEPLOY
	req := PDPRequest{
		RequestID: "req-deploy-1",
		Effect: EffectDescriptor{
			EffectType:        "DEPLOY",
			EffectID:          "eff-d1",
			EffectPayloadHash: "hash",
		},
		Subject: SubjectDescriptor{ActorID: "admin"},
		Context: ContextDescriptor{
			Time: TimeDescriptor{Timestamp: time.Now()},
		},
	}

	// 4. Evaluate
	resp, err := pdp.Evaluate(context.Background(), req)
	require.NoError(t, err)

	// 5. Verify DENY due to failed build check
	assert.Equal(t, DecisionDeny, resp.Decision)
	assert.Contains(t, resp.Trace.RulesFired, "system.deny.deploy.build_failed")
}

func TestPDP_FactCheck_DeployGate_Pass(t *testing.T) {
	// 1. Setup Oracle with PASSING build
	oracle := &MockFactOracle{
		Facts: map[string]interface{}{
			"repo:helm|build_status": "passing",
		},
	}

	pdp, err := NewCELPolicyDecisionPoint("sha256:test", oracle)
	require.NoError(t, err)

	req := PDPRequest{
		RequestID: "req-deploy-2",
		Effect:    EffectDescriptor{EffectType: "DEPLOY"},
	}

	resp, err := pdp.Evaluate(context.Background(), req)
	require.NoError(t, err)

	// Should NOT deny, but Require Approval (default high risk logic)
	// If it was denied, it would be DecisionDeny
	assert.Equal(t, DecisionRequireApproval, resp.Decision)

	// Ensure the deny rule did NOT fire
	for _, rule := range resp.Trace.RulesFired {
		assert.NotEqual(t, "system.deny.deploy.build_failed", rule)
	}
}
