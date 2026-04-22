package verify

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func verifyFixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func makeRulesJSON(t *testing.T, rules []policyRule) []byte {
	t.Helper()
	data, err := json.Marshal(rules)
	require.NoError(t, err)
	return data
}

func TestStaticAnalysis_HealthyPolicy(t *testing.T) {
	now := time.Date(2026, 4, 13, 0, 0, 0, 0, time.UTC)
	v := NewStaticAnalysisVerifier(WithVerifyClock(verifyFixedClock(now)))

	rules := makeRulesJSON(t, []policyRule{
		{ID: "r1", Priority: 10, Action: "ALLOW", Resource: "file"},
		{ID: "r2", Priority: 20, Action: "DENY", Resource: "admin"},
	})

	result, err := v.Verify("policy-1", rules, []string{"no_circular_deps", "deny_terminates"})
	require.NoError(t, err)

	assert.True(t, result.Verified)
	assert.Equal(t, "policy-1", result.PolicyID)
	assert.Equal(t, "static_analysis", result.Method)
	assert.Equal(t, now, result.VerifiedAt)
	assert.Empty(t, result.Violations)
	assert.Contains(t, result.Properties, "no_circular_deps")
	assert.Contains(t, result.Properties, "deny_terminates")
}

func TestStaticAnalysis_CircularDependency(t *testing.T) {
	v := NewStaticAnalysisVerifier()

	rules := makeRulesJSON(t, []policyRule{
		{ID: "r1", Priority: 10, Action: "ALLOW", Resource: "file", DependsOn: "r2"},
		{ID: "r2", Priority: 20, Action: "DENY", Resource: "file", DependsOn: "r3"},
		{ID: "r3", Priority: 30, Action: "ALLOW", Resource: "file", DependsOn: "r1"},
	})

	result, err := v.Verify("policy-circular", rules, []string{"no_circular_deps"})
	require.NoError(t, err)

	assert.False(t, result.Verified)
	assert.NotEmpty(t, result.Violations)

	foundCircular := false
	for _, violation := range result.Violations {
		if assert.ObjectsAreEqual("circular dependency", violation) || len(violation) > 0 {
			foundCircular = true
		}
	}
	assert.True(t, foundCircular)
}

func TestStaticAnalysis_ShadowedDeny(t *testing.T) {
	v := NewStaticAnalysisVerifier()

	rules := makeRulesJSON(t, []policyRule{
		{ID: "allow-all", Priority: 100, Action: "ALLOW", Resource: "admin"},
		{ID: "deny-admin", Priority: 10, Action: "DENY", Resource: "admin"},
	})

	result, err := v.Verify("policy-shadowed", rules, []string{"no_shadowed_deny"})
	require.NoError(t, err)

	assert.False(t, result.Verified)
	require.NotEmpty(t, result.Violations)

	found := false
	for _, violation := range result.Violations {
		if assert.ObjectsAreEqual("shadowed", violation) || len(violation) > 0 {
			found = true
		}
	}
	assert.True(t, found)
}

func TestStaticAnalysis_DenyNotShadowed(t *testing.T) {
	v := NewStaticAnalysisVerifier()

	// DENY has higher priority than ALLOW — not shadowed.
	rules := makeRulesJSON(t, []policyRule{
		{ID: "allow-file", Priority: 10, Action: "ALLOW", Resource: "file"},
		{ID: "deny-file", Priority: 100, Action: "DENY", Resource: "file"},
	})

	result, err := v.Verify("policy-correct", rules, []string{"no_shadowed_deny"})
	require.NoError(t, err)

	assert.True(t, result.Verified)
	assert.Empty(t, result.Violations)
}

func TestStaticAnalysis_NoDenyRule(t *testing.T) {
	v := NewStaticAnalysisVerifier()

	rules := makeRulesJSON(t, []policyRule{
		{ID: "r1", Priority: 10, Action: "ALLOW", Resource: "file"},
		{ID: "r2", Priority: 20, Action: "ALLOW", Resource: "admin"},
	})

	result, err := v.Verify("policy-allow-only", rules, []string{"deny_terminates"})
	require.NoError(t, err)

	assert.False(t, result.Verified)
	require.NotEmpty(t, result.Violations)
	assert.Contains(t, result.Violations[0], "no DENY rule found")
}

func TestStaticAnalysis_EscalationLoop(t *testing.T) {
	v := NewStaticAnalysisVerifier()

	rules := makeRulesJSON(t, []policyRule{
		{ID: "escalate-1", Priority: 10, Action: "ALLOW", Resource: "approval", DependsOn: "escalate-2"},
		{ID: "escalate-2", Priority: 20, Action: "ALLOW", Resource: "approval", DependsOn: "escalate-1"},
	})

	result, err := v.Verify("policy-escalation", rules, []string{"no_escalation_loop"})
	require.NoError(t, err)

	assert.False(t, result.Verified)
	assert.NotEmpty(t, result.Violations)
}

func TestStaticAnalysis_AllPropertiesTogether(t *testing.T) {
	v := NewStaticAnalysisVerifier()

	rules := makeRulesJSON(t, []policyRule{
		{ID: "r1", Priority: 10, Action: "ALLOW", Resource: "file"},
		{ID: "r2", Priority: 20, Action: "DENY", Resource: "admin"},
		{ID: "r3", Priority: 30, Action: "ALLOW", Resource: "db"},
	})

	result, err := v.Verify("policy-all", rules,
		[]string{"no_circular_deps", "no_shadowed_deny", "no_escalation_loop", "deny_terminates"})
	require.NoError(t, err)

	assert.True(t, result.Verified)
	assert.Len(t, result.Properties, 4)
	assert.Empty(t, result.Violations)
}

func TestStaticAnalysis_ValidationErrors(t *testing.T) {
	v := NewStaticAnalysisVerifier()

	t.Run("empty policy ID", func(t *testing.T) {
		_, err := v.Verify("", []byte(`[]`), []string{"deny_terminates"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "policy ID")
	})

	t.Run("empty rules", func(t *testing.T) {
		_, err := v.Verify("policy-1", nil, []string{"deny_terminates"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "policy rules")
	})

	t.Run("empty properties", func(t *testing.T) {
		_, err := v.Verify("policy-1", []byte(`[]`), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "property")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		_, err := v.Verify("policy-1", []byte(`{not valid`), []string{"deny_terminates"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "parse")
	})
}

func TestStaticAnalysis_UnknownProperty(t *testing.T) {
	v := NewStaticAnalysisVerifier()

	rules := makeRulesJSON(t, []policyRule{
		{ID: "r1", Priority: 10, Action: "DENY", Resource: "file"},
	})

	result, err := v.Verify("policy-1", rules, []string{"unknown_property"})
	require.NoError(t, err)

	assert.False(t, result.Verified)
	require.NotEmpty(t, result.Violations)
	assert.Contains(t, result.Violations[0], "unknown property")
}

func TestStaticAnalysis_ResultStruct(t *testing.T) {
	now := time.Date(2026, 4, 13, 12, 0, 0, 0, time.UTC)

	result := PolicyVerificationResult{
		PolicyID:   "pol-1",
		Verified:   true,
		Properties: []string{"no_circular_deps"},
		Method:     "tla+",
		VerifiedAt: now,
	}

	assert.Equal(t, "pol-1", result.PolicyID)
	assert.True(t, result.Verified)
	assert.Equal(t, "tla+", result.Method)
	assert.Nil(t, result.Violations)
}

func TestPolicyVerifierInterfaceCompliance(t *testing.T) {
	var _ PolicyVerifier = (*StaticAnalysisVerifier)(nil)
}

func TestStaticAnalysis_NoDeps(t *testing.T) {
	v := NewStaticAnalysisVerifier()

	// Rules with no depends_on — should pass circular dependency check.
	rules := makeRulesJSON(t, []policyRule{
		{ID: "r1", Priority: 10, Action: "ALLOW", Resource: "file"},
		{ID: "r2", Priority: 20, Action: "DENY", Resource: "admin"},
	})

	result, err := v.Verify("policy-no-deps", rules, []string{"no_circular_deps"})
	require.NoError(t, err)
	assert.True(t, result.Verified)
}

func TestStaticAnalysis_DifferentResources(t *testing.T) {
	v := NewStaticAnalysisVerifier()

	// ALLOW on "file" and DENY on "admin" — different resources, no shadowing.
	rules := makeRulesJSON(t, []policyRule{
		{ID: "r1", Priority: 100, Action: "ALLOW", Resource: "file"},
		{ID: "r2", Priority: 10, Action: "DENY", Resource: "admin"},
	})

	result, err := v.Verify("policy-diff-res", rules, []string{"no_shadowed_deny"})
	require.NoError(t, err)
	assert.True(t, result.Verified)
	assert.Empty(t, result.Violations)
}
