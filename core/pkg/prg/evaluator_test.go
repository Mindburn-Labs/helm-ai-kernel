package prg

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateRequirementSet_SimpleLogic(t *testing.T) {
	pe, err := NewPolicyEngine()
	require.NoError(t, err)

	// Rule: risk_score < 50
	rs := RequirementSet{
		ID: "req-1",
		Requirements: []Requirement{
			{ID: "r1", Expression: "input.risk_score < 50"},
		},
	}

	// Case 1: Pass
	inputPass := map[string]interface{}{
		"risk_score": 20,
	}
	pass, err := pe.EvaluateRequirementSet(rs, inputPass)
	assert.NoError(t, err)
	assert.True(t, pass)

	// Case 2: Fail
	inputFail := map[string]interface{}{
		"risk_score": 80,
	}
	pass, err = pe.EvaluateRequirementSet(rs, inputFail)
	assert.NoError(t, err)
	assert.False(t, pass)
}

func TestEvaluateRequirementSet_ComplexLogic(t *testing.T) {
	pe, err := NewPolicyEngine()
	require.NoError(t, err)

	// Rule: (action == "deploy" AND role == "admin") OR (risk < 10)
	// Modeled as OR parent with two children
	rs := RequirementSet{
		Logic: OR,
		Children: []RequirementSet{
			{
				Logic: AND,
				Requirements: []Requirement{
					{Expression: "input.action == 'deploy'"},
					{Expression: "input.role == 'admin'"},
				},
			},
			{
				Requirements: []Requirement{
					{Expression: "input.risk < 10"},
				},
			},
		},
	}

	// Case 1: Deploy as Admin (Pass)
	pass, err := pe.EvaluateRequirementSet(rs, map[string]interface{}{
		"action": "deploy", "role": "admin", "risk": 100,
	})
	assert.NoError(t, err)
	assert.True(t, pass)

	// Case 2: Deploy as User (Fail)
	pass, err = pe.EvaluateRequirementSet(rs, map[string]interface{}{
		"action": "deploy", "role": "user", "risk": 100,
	})
	assert.NoError(t, err)
	assert.False(t, pass)

	// Case 3: Low Risk (Pass)
	pass, err = pe.EvaluateRequirementSet(rs, map[string]interface{}{
		"action": "nuke", "role": "user", "risk": 5,
	})
	assert.NoError(t, err)
	assert.True(t, pass)
}
